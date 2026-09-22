import { Env, ClientRecord, UserMappingRecord, BrokerSession, DownstreamAuthCode } from './types';
import { getProvider, getProviderCredentials } from './providers';
import { getIssuer } from './utils/origin';
import { getOidcConfiguration, getJwks } from './utils/oidc';
import { verifyPkce } from './utils/pkce';
import { mintDownstreamIdToken } from './utils/jwt';
import { verifyCloudflareAccess } from './utils/access';
import { renderAdminConsoleHtml } from './views/adminConsole';
import { parseClientCredentials } from './utils/clientAuth';
import { parseRequestObjectClaims } from './utils/requestObject';
import { renderFormPostHtml, renderFormPostErrorHtml } from './views/formPost';

// Server-side secure secret generator fallback
function generateSecureSecret(length = 48): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);

  let secret = '';
  for (let i = 0; i < length; i++) {
    secret += chars[randomValues[i] % chars.length];
  }
  return secret;
}

// Inject CORS headers for OIDC API endpoints
function addCorsHeaders(response: Response): Response {
  response.headers.set('Access-Control-Allow-Origin', '*');
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return response;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname.replace(/\/+$/, '');
    const issuer = getIssuer(request);

    // -------------------------------------------------------------
    // CORS Preflight Handler
    // -------------------------------------------------------------
    if (request.method === 'OPTIONS') {
      return addCorsHeaders(new Response(null, { status: 204 }));
    }

    // -------------------------------------------------------------
    // 0. Favicon Handler (Emoji 🔐)
    // -------------------------------------------------------------
    if (pathname === '/favicon.ico') {
      const emojiFavicon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y="80" font-size="80">🔐</text></svg>';
      return new Response(emojiFavicon, {
        headers: {
          'Content-Type': 'image/svg+xml',
          'Cache-Control': 'public, max-age=86400'
        }
      });
    }

    // -------------------------------------------------------------
    // 1. OIDC Discovery Document
    // -------------------------------------------------------------
    if (pathname === '/.well-known/openid-configuration') {
      return Response.json(getOidcConfiguration(issuer));
    }

    // -------------------------------------------------------------
    // 2. JWKS Public Keys
    // -------------------------------------------------------------
    if (pathname === '/.well-known/jwks.json') {
      return await getJwks(env);
    }

    // -------------------------------------------------------------
    // 3. Downstream Authorization -> Redirect to Upstream Provider
    // -------------------------------------------------------------
    if (pathname === '/authorize') {
      // Parse Request Object (OIDC Core §6 — request parameter)
      const requestParam = url.searchParams.get('request');
      const requestClaims = requestParam ? parseRequestObjectClaims(requestParam) : {};

      // Request object claims take precedence over URL query parameters
      const getParam = (key: string) => requestClaims[key] !== undefined ? requestClaims[key] : url.searchParams.get(key);

      // Strict response_type validation (OIDC Basic OP requirement)
      const responseType = getParam('response_type');
      if (responseType !== 'code') {
        return Response.json({
          error: 'unsupported_response_type',
          error_description: 'Only authorization code flow (response_type=code) is supported.'
        }, { status: 400 });
      }

      const clientId = getParam('client_id');
      const redirectUri = getParam('redirect_uri');
      const state = getParam('state') || '';
      const nonce = getParam('nonce') || '';
      const codeChallenge = getParam('code_challenge') || '';
      const codeChallengeMethod = getParam('code_challenge_method') || '';
      const prompt = getParam('prompt');
      const maxAgeStr = getParam('max_age');
      const maxAge = maxAgeStr ? parseInt(maxAgeStr, 10) : undefined;
      const responseMode = (getParam('response_mode') || 'query') as 'query' | 'form_post';

      if (!clientId || !redirectUri) {
        return Response.json({
          error: 'invalid_request',
          error_description: 'Missing client_id or redirect_uri'
        }, { status: 400 });
      }

      const client = await env.DB.prepare('SELECT * FROM clients WHERE client_id = ? AND is_active = 1')
        .bind(clientId)
        .first<ClientRecord>();

      if (!client) {
        return Response.json({
          error: 'unauthorized_client',
          error_description: 'Unauthorized or inactive client_id'
        }, { status: 403 });
      }

      const allowedUris: string[] = JSON.parse(client.redirect_uris || '[]');
      if (!allowedUris.includes(redirectUri)) {
        return Response.json({
          error: 'invalid_request',
          error_description: 'Unauthorized redirect_uri'
        }, { status: 400 });
      }

      // ── Session / prompt handling ──────────────────────────────
      //
      // We only honour an existing session cookie to:
      //   a) satisfy prompt=none (return login_required if no valid session), or
      //   b) carry forward auth_time when max_age is satisfied so the downstream
      //      id_token reflects the original authentication time.
      //
      // In all other cases the user is sent to the upstream provider unconditionally.

      let sessionAuthTime: number | undefined = undefined;

      const cookies = request.headers.get('Cookie') || '';
      const sessionMatch = cookies.match(/user_session=([^;]+)/);
      if (sessionMatch) {
        try {
          const cookieData = JSON.parse(decodeURIComponent(sessionMatch[1]));
          const currentTime = Math.floor(Date.now() / 1000);
          const cookieAuthTime: number | undefined = cookieData.authTime;
          const hasSession = cookieAuthTime !== undefined;
          const maxAgeSatisfied = maxAge !== undefined && hasSession && (currentTime - cookieAuthTime!) < maxAge;

          if (prompt === 'none') {
            // For prompt=none, decide immediately whether the session is acceptable.
            const sessionAccepted = maxAge !== undefined ? maxAgeSatisfied : hasSession;
            if (!sessionAccepted) {
              const errorUrl = new URL(redirectUri);
              errorUrl.searchParams.set('error', 'login_required');
              errorUrl.searchParams.set('error_description', 'User is not authenticated or session has expired');
              if (state) errorUrl.searchParams.set('state', state);
              return Response.redirect(errorUrl.toString(), 302);
            }
            sessionAuthTime = cookieAuthTime;
          } else if (maxAgeSatisfied) {
            // Non-none prompt: carry the original auth_time forward when max_age is met,
            // so the downstream id_token reflects when the user actually authenticated.
            sessionAuthTime = cookieAuthTime;
          }
          // Otherwise, sessionAuthTime stays undefined and will be set after the upstream login.
        } catch {
          // Ignore cookie parse errors — treat as no session
        }
      } else if (prompt === 'none') {
        // No cookie at all and prompt=none → must return login_required immediately
        const errorUrl = new URL(redirectUri);
        errorUrl.searchParams.set('error', 'login_required');
        errorUrl.searchParams.set('error_description', 'User is not authenticated');
        if (state) errorUrl.searchParams.set('state', state);
        return Response.redirect(errorUrl.toString(), 302);
      }

      // ── PKCE validation ────────────────────────────────────────
      const requirePkce = client.require_pkce !== 0;
      if (requirePkce) {
        if (!codeChallenge || codeChallengeMethod !== 'S256') {
          return Response.json({
            error: 'invalid_request',
            error_description: 'code_challenge and code_challenge_method=S256 are required'
          }, { status: 400 });
        }
      } else if (codeChallengeMethod && codeChallengeMethod !== 'S256') {
        return Response.json({
          error: 'invalid_request',
          error_description: 'Only S256 is supported for code_challenge_method'
        }, { status: 400 });
      }

      // Validate response_mode
      if (responseMode !== 'query' && responseMode !== 'form_post') {
        return Response.json({
          error: 'invalid_request',
          error_description: 'Unsupported response_mode. Only query or form_post are supported.'
        }, { status: 400 });
      }

      const brokerSessionId = crypto.randomUUID();
      const sessionData: BrokerSession = {
        clientId,
        redirectUri,
        state,
        nonce,
        requirePkce,
        codeChallenge,
        codeChallengeMethod,
        responseMode,
        authTime: sessionAuthTime
      };

      await env.SESSIONS_KV.put(
        `session:${brokerSessionId}`,
        JSON.stringify(sessionData),
        { expirationTtl: 300 }
      );

      const provider = getProvider(client.provider, env);
      const credentials = getProviderCredentials(client.provider, env);
      const upstreamAuthUrl = provider.buildAuthUrl({
        clientId: credentials.clientId,
        redirectUri: `${issuer}/callback`,
        state: brokerSessionId
      });

      return Response.redirect(upstreamAuthUrl, 302);
    }

    // -------------------------------------------------------------
    // 4. Upstream Callback -> Verify User & Issue Downstream Code
    // -------------------------------------------------------------
    if (pathname === '/callback' && (request.method === 'GET' || request.method === 'POST')) {
      let code: string | null = null;
      let brokerSessionId: string | null = null;
      if (request.method === 'POST') {
        const form = await request.formData();
        code = form.get('code') as string | null;
        brokerSessionId = form.get('state') as string | null;
      } else {
        code = url.searchParams.get('code');
        brokerSessionId = url.searchParams.get('state');
      }

      if (!code || !brokerSessionId) {
        return Response.json({
          error: 'invalid_request',
          error_description: 'Invalid callback parameters'
        }, { status: 400 });
      }

      const sessionRaw = await env.SESSIONS_KV.get(`session:${brokerSessionId}`);
      if (!sessionRaw) {
        return Response.json({
          error: 'invalid_request',
          error_description: 'Session expired or invalid'
        }, { status: 403 });
      }
      const session: BrokerSession = JSON.parse(sessionRaw);
      await env.SESSIONS_KV.delete(`session:${brokerSessionId}`);

      const sessionClient = await env.DB.prepare('SELECT provider FROM clients WHERE client_id = ? AND is_active = 1')
        .bind(session.clientId)
        .first<{ provider: string }>();
      if (!sessionClient) {
        return Response.json({
          error: 'unauthorized_client',
          error_description: 'Client no longer active'
        }, { status: 403 });
      }

      const provider = getProvider(sessionClient.provider, env);
      const credentials = getProviderCredentials(sessionClient.provider, env);
      let upstreamUser: Awaited<ReturnType<typeof provider.exchangeCode>>;
      try {
        upstreamUser = await provider.exchangeCode({
          code,
          clientId: credentials.clientId,
          clientSecret: credentials.clientSecret,
          redirectUri: `${issuer}/callback`
        });
      } catch (err: any) {
        console.error('Upstream provider error:', err?.message);
        return Response.json({
          error: 'server_error',
          error_description: 'Upstream identity verification failed'
        }, { status: 502 });
      }

      const mappedUser = await env.DB.prepare(`
        SELECT * FROM user_mappings
        WHERE email = ?
          AND is_active = 1
          AND (client_id = ? OR client_id = '*')
        ORDER BY CASE WHEN client_id = ? THEN 0 ELSE 1 END
        LIMIT 1
      `)
        .bind(upstreamUser.email, session.clientId, session.clientId)
        .first<UserMappingRecord>();

      if (!mappedUser) {
        return Response.json({
          error: 'access_denied',
          error_description: 'User is not authorized for this application'
        }, { status: 403 });
      }

      // Record last login and store the upstream sub on first login.
      // google_sub stores any upstream provider sub (named for backwards compatibility).
      await env.DB.prepare(
        'UPDATE user_mappings SET last_login = CURRENT_TIMESTAMP, google_sub = COALESCE(google_sub, ?) WHERE id = ?'
      )
        .bind(upstreamUser.sub, mappedUser.id)
        .run();

      const authTime = session.authTime || Math.floor(Date.now() / 1000);
      const brokerCode = crypto.randomUUID();
      const codePayload: DownstreamAuthCode = {
        clientId: session.clientId,
        sub: upstreamUser.sub,
        email: upstreamUser.email,
        emailVerified: upstreamUser.email_verified,
        username: mappedUser.username,
        name: mappedUser.display_name || upstreamUser.name || mappedUser.username,
        nonce: session.nonce,
        requirePkce: session.requirePkce,
        codeChallenge: session.codeChallenge,
        codeChallengeMethod: session.codeChallengeMethod,
        authTime
      };

      await env.SESSIONS_KV.put(
        `code:${brokerCode}`,
        JSON.stringify(codePayload),
        { expirationTtl: 120 }
      );

      const sessionCookie = `user_session=${encodeURIComponent(JSON.stringify({
        email: upstreamUser.email,
        authTime
      }))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`;

      // Handle Form Post response mode
      if (session.responseMode === 'form_post') {
        const error = url.searchParams.get('error');
        if (error) {
          const errorDescription = url.searchParams.get('error_description');
          return new Response(renderFormPostErrorHtml(session.redirectUri, error, errorDescription, session.state), {
            status: 200,
            headers: {
              'Content-Type': 'text/html',
              'Cache-Control': 'no-store, no-cache, must-revalidate',
              'Pragma': 'no-cache',
              'Set-Cookie': sessionCookie
            }
          });
        }

        return new Response(renderFormPostHtml(session.redirectUri, brokerCode, session.state), {
          status: 200,
          headers: {
            'Content-Type': 'text/html',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache',
            'Set-Cookie': sessionCookie
          }
        });
      }

      // Default: Standard 302 Redirect (query mode)
      const targetUrl = new URL(session.redirectUri);
      targetUrl.searchParams.set('code', brokerCode);
      if (session.state) targetUrl.searchParams.set('state', session.state);

      return new Response(null, {
        status: 302,
        headers: {
          'Location': targetUrl.toString(),
          'Set-Cookie': sessionCookie
        }
      });
    }

    // -------------------------------------------------------------
    // 5. Downstream Token Endpoint
    // -------------------------------------------------------------
    if (pathname === '/token' && request.method === 'POST') {
      const { clientId, clientSecret, code, codeVerifier } = await parseClientCredentials(request);

      if (!code || !clientId) {
        return addCorsHeaders(Response.json({
          error: 'invalid_request',
          error_description: 'Missing code or client_id'
        }, { status: 400 }));
      }

      const client = await env.DB.prepare('SELECT * FROM clients WHERE client_id = ? AND is_active = 1')
        .bind(clientId)
        .first<ClientRecord>();

      if (!client) {
        return addCorsHeaders(Response.json({
          error: 'invalid_client',
          error_description: 'Client not found or inactive'
        }, { status: 401 }));
      }

      if (client.client_secret && client.client_secret !== clientSecret) {
        return addCorsHeaders(Response.json({
          error: 'invalid_client',
          error_description: 'Unauthorized client credentials'
        }, { status: 401 }));
      }

      const authDataRaw = await env.SESSIONS_KV.get(`code:${code}`);
      if (!authDataRaw) {
        return addCorsHeaders(Response.json({
          error: 'invalid_grant',
          error_description: 'Code expired or invalid'
        }, { status: 400 }));
      }
      const authData: DownstreamAuthCode = JSON.parse(authDataRaw);
      await env.SESSIONS_KV.delete(`code:${code}`);

      if (authData.clientId !== clientId) {
        return addCorsHeaders(Response.json({
          error: 'invalid_grant',
          error_description: 'Client mismatch'
        }, { status: 400 }));
      }

      if (authData.requirePkce) {
        if (!authData.codeChallenge || !codeVerifier) {
          return addCorsHeaders(Response.json({
            error: 'invalid_request',
            error_description: 'Missing code_challenge or code_verifier'
          }, { status: 400 }));
        }
        const isPkceValid = await verifyPkce(codeVerifier, authData.codeChallenge, authData.codeChallengeMethod || 'S256');
        if (!isPkceValid) {
          return addCorsHeaders(Response.json({
            error: 'invalid_grant',
            error_description: 'PKCE verification failed'
          }, { status: 400 }));
        }
      }

      const idToken = await mintDownstreamIdToken({
        sub: authData.sub,
        email: authData.email,
        emailVerified: authData.emailVerified,
        username: authData.username,
        name: authData.name,
        clientId: authData.clientId,
        issuer,
        nonce: authData.nonce,
        authTime: authData.authTime,
        privateKeyJwk: env.BROKER_PRIVATE_KEY_JWK
      });

      const accessToken = crypto.randomUUID();

      await env.SESSIONS_KV.put(
        `access_token:${accessToken}`,
        JSON.stringify({
          sub: authData.sub,
          email: authData.email,
          emailVerified: authData.emailVerified,
          username: authData.username,
          name: authData.name
        }),
        { expirationTtl: 3600 }
      );

      // Maintain a reverse index so /logout can purge all tokens for this user.
      // user_tokens:{email} holds a JSON array of active access token UUIDs.
      const userTokensKey = `user_tokens:${authData.email}`;
      const existingIndexRaw = await env.SESSIONS_KV.get(userTokensKey);
      const existingTokens: string[] = existingIndexRaw ? JSON.parse(existingIndexRaw) : [];
      existingTokens.push(accessToken);
      await env.SESSIONS_KV.put(userTokensKey, JSON.stringify(existingTokens), { expirationTtl: 3600 });

      return addCorsHeaders(Response.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: idToken
      }));
    }

    // -------------------------------------------------------------
    // 6. Userinfo Endpoint (OIDC Standard)
    // -------------------------------------------------------------
    if (pathname === '/userinfo') {
      const authHeader = request.headers.get('authorization') || '';
      const accessToken = authHeader.replace(/^Bearer\s+/i, '').trim();

      if (!accessToken) {
        return addCorsHeaders(Response.json({
          error: 'unauthorized',
          error_description: 'Missing access token'
        }, { status: 401 }));
      }

      const cachedRaw = await env.SESSIONS_KV.get(`access_token:${accessToken}`);
      if (!cachedRaw) {
        return addCorsHeaders(Response.json({
          error: 'invalid_token',
          error_description: 'Token expired or invalid'
        }, { status: 401 }));
      }

      const userData = JSON.parse(cachedRaw);
      return addCorsHeaders(Response.json({
        sub: userData.sub,
        email: userData.email,
        email_verified: userData.emailVerified === true,
        username: userData.username,
        preferred_username: userData.username,
        name: userData.name
      }));
    }

    // -------------------------------------------------------------
    // 7. Token Revocation Endpoint (RFC 7009)
    // -------------------------------------------------------------
    if (pathname === '/revoke' && request.method === 'POST') {
      const { clientId, clientSecret, token } = await parseClientCredentials(request);

      if (!token) {
        return addCorsHeaders(Response.json({
          error: 'invalid_request',
          error_description: 'Missing token parameter'
        }, { status: 400 }));
      }

      if (clientId) {
        const client = await env.DB.prepare('SELECT * FROM clients WHERE client_id = ? AND is_active = 1')
          .bind(clientId)
          .first<ClientRecord>();

        if (!client || (client.client_secret && client.client_secret !== clientSecret)) {
          return addCorsHeaders(Response.json({
            error: 'invalid_client',
            error_description: 'Unauthorized client credentials'
          }, { status: 401 }));
        }
      }

      await env.SESSIONS_KV.delete(`access_token:${token}`);
      return addCorsHeaders(new Response(null, { status: 200 }));
    }

    // -------------------------------------------------------------
    // 8. Logout Endpoint (RP-Initiated Single Logout)
    // -------------------------------------------------------------
    if (pathname === '/logout') {
      const postLogoutRedirectUri = url.searchParams.get('post_logout_redirect_uri');
      const idTokenHint = url.searchParams.get('id_token_hint');

      // Identify the user to purge tokens for.
      // Prefer id_token_hint (OIDC spec, covers back-channel & RP-initiated logout).
      // Fall back to the broker session cookie (browser-initiated logout without hint).
      let logoutEmail: string | undefined;

      if (idTokenHint) {
        try {
          // Decode without verification — this is our own token, we trust the payload shape.
          // We only need the email claim to look up the reverse index.
          const parts = idTokenHint.split('.');
          if (parts.length === 3) {
            const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
            logoutEmail = payload.email as string | undefined;
          }
        } catch {
          // Malformed hint — ignore and proceed without purging
        }
      }

      if (!logoutEmail) {
        try {
          const logoutCookies = request.headers.get('Cookie') || '';
          const logoutSessionMatch = logoutCookies.match(/user_session=([^;]+)/);
          if (logoutSessionMatch) {
            const cookieData = JSON.parse(decodeURIComponent(logoutSessionMatch[1]));
            logoutEmail = cookieData.email as string | undefined;
          }
        } catch {
          // Ignore cookie parse errors
        }
      }

      // Purge all active access tokens for the identified user
      if (logoutEmail) {
        const userTokensKey = `user_tokens:${logoutEmail}`;
        const indexRaw = await env.SESSIONS_KV.get(userTokensKey);
        if (indexRaw) {
          const tokenIds: string[] = JSON.parse(indexRaw);
          await Promise.all([
            ...tokenIds.map(id => env.SESSIONS_KV.delete(`access_token:${id}`)),
            env.SESSIONS_KV.delete(userTokensKey)
          ]);
        }
      }

      // Clear the broker session cookie regardless
      const clearCookie = 'user_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';

      if (postLogoutRedirectUri) {
        const allClients = await env.DB.prepare('SELECT redirect_uris FROM clients WHERE is_active = 1').all<{ redirect_uris: string }>();
        const allAllowedUris = allClients.results.flatMap(c => {
          try { return JSON.parse(c.redirect_uris) as string[]; } catch { return []; }
        });

        const getOrigin = (u: string) => { try { return new URL(u).origin; } catch { return ''; } };
        const requestedOrigin = getOrigin(postLogoutRedirectUri);
        const isAllowed = !!requestedOrigin && allAllowedUris.some(u => getOrigin(u) === requestedOrigin);

        if (!isAllowed) {
          return new Response('Invalid post_logout_redirect_uri: not registered for any active client.', { status: 400 });
        }

        return new Response(null, {
          status: 302,
          headers: {
            'Location': postLogoutRedirectUri,
            'Set-Cookie': clearCookie
          }
        });
      }

      return new Response('You have been logged out.', {
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Set-Cookie': clearCookie
        }
      });
    }

    // -------------------------------------------------------------
    // 9. Zero Trust Protected Admin Console & APIs
    // -------------------------------------------------------------
    if (pathname.startsWith(env.ADMIN_ROUTE_PATH)) {
      // Defense-in-depth: require EITHER a valid Cloudflare Access session OR the Admin API Token
      const cfAccessEmail = request.headers.get('Cf-Access-Authenticated-User-Email');
      const authHeader = request.headers.get('Authorization');
      const hasValidToken = !!(env.ADMIN_API_TOKEN && authHeader === `Bearer ${env.ADMIN_API_TOKEN}`);

      if (!cfAccessEmail && !hasValidToken) {
        return new Response('Unauthorized: Missing valid Cloudflare Access session or Admin API Token.', { status: 401 });
      }

      // Verify Cloudflare Access JWT to get the confirmed user email for the UI
      let accessUserEmail = cfAccessEmail || 'admin';
      if (cfAccessEmail) {
        const accessUser = await verifyCloudflareAccess(request, env);
        if (accessUser?.email) {
          accessUserEmail = accessUser.email;
        }
      }

      const apiPath = pathname.replace(env.ADMIN_ROUTE_PATH, '');

      if (apiPath === '/api/data' && request.method === 'GET') {
        const clients = await env.DB.prepare('SELECT * FROM clients ORDER BY created_at DESC').all();
        const mappings = await env.DB.prepare('SELECT * FROM user_mappings ORDER BY created_at DESC').all();
        return Response.json({
          clients: clients.results.map((c: any) => ({ ...c, redirect_uris: JSON.parse(c.redirect_uris || '[]') })),
          mappings: mappings.results
        });
      }

      if (apiPath === '/api/providers' && request.method === 'GET') {
        const configured = [
          { id: 'google',    label: 'Google',    ready: !!(env.UPSTREAM_GOOGLE_CLIENT_ID    && env.UPSTREAM_GOOGLE_CLIENT_SECRET) },
          { id: 'microsoft', label: 'Microsoft', ready: !!(env.UPSTREAM_MICROSOFT_CLIENT_ID && env.UPSTREAM_MICROSOFT_CLIENT_SECRET) },
          { id: 'github',    label: 'GitHub',    ready: !!(env.UPSTREAM_GITHUB_CLIENT_ID    && env.UPSTREAM_GITHUB_CLIENT_SECRET) },
          { id: 'apple',     label: 'Apple',     ready: !!(env.UPSTREAM_APPLE_CLIENT_ID     && env.UPSTREAM_APPLE_CLIENT_SECRET && env.UPSTREAM_APPLE_TEAM_ID && env.UPSTREAM_APPLE_KEY_ID) },
        ];
        return Response.json(configured);
      }

      if (apiPath === '/api/clients' && request.method === 'POST') {
        const b = (await request.json()) as any;

        if (!b.client_id || typeof b.client_id !== 'string' || !b.client_name || typeof b.client_name !== 'string') {
          return Response.json({ error: 'invalid_request', error_description: 'client_id and client_name are required strings' }, { status: 400 });
        }
        if (!Array.isArray(b.redirect_uris) || b.redirect_uris.length === 0) {
          return Response.json({ error: 'invalid_request', error_description: 'redirect_uris must be a non-empty array' }, { status: 400 });
        }

        let finalSecret = (b.client_secret || '').trim();
        if (!finalSecret) {
          finalSecret = generateSecureSecret(48);
          console.log(`[SECURITY] Auto-generated 48-char secret for client: ${b.client_id}`);
        } else if (finalSecret.length < 32) {
          return Response.json({
            error: 'invalid_request',
            error_description: 'Custom client_secret must be at least 32 characters long for security'
          }, { status: 400 });
        }

        await env.DB.prepare('INSERT OR REPLACE INTO clients (client_id, client_name, client_secret, redirect_uris, provider, require_pkce, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)')
          .bind(b.client_id.trim(), b.client_name.trim(), finalSecret, JSON.stringify(b.redirect_uris), b.provider || 'google', b.require_pkce !== undefined ? (b.require_pkce ? 1 : 0) : 1, b.is_active ? 1 : 0)
          .run();
        return Response.json({ success: true });
      }

      if (apiPath.startsWith('/api/clients/') && request.method === 'DELETE') {
        const id = decodeURIComponent(apiPath.replace('/api/clients/', ''));
        await env.DB.prepare('DELETE FROM clients WHERE client_id = ?').bind(id).run();
        return Response.json({ success: true });
      }

      if (apiPath === '/api/mappings' && request.method === 'POST') {
        const b = (await request.json()) as any;

        if (!b.email || typeof b.email !== 'string') {
          return Response.json({ error: 'invalid_request', error_description: 'email is required' }, { status: 400 });
        }
        if (!b.username || typeof b.username !== 'string') {
          return Response.json({ error: 'invalid_request', error_description: 'username is required' }, { status: 400 });
        }

        const targetClient = b.client_id || '*';
        const originalClient = b.original_client_id;

        if (originalClient && originalClient !== targetClient) {
          await env.DB.prepare('DELETE FROM user_mappings WHERE email = ? AND client_id = ?')
            .bind(b.email.toLowerCase().trim(), originalClient).run();
        }

        await env.DB.prepare(`
          INSERT INTO user_mappings (email, client_id, username, display_name, is_active)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(email, client_id) DO UPDATE SET
            username = excluded.username,
            display_name = excluded.display_name,
            is_active = excluded.is_active
        `)
          .bind(b.email.toLowerCase().trim(), targetClient, b.username.trim(), (b.display_name || '').trim(), b.is_active ? 1 : 0)
          .run();

        return Response.json({ success: true });
      }

      if (apiPath.startsWith('/api/mappings/') && request.method === 'DELETE') {
        const rawParam = decodeURIComponent(apiPath.replace('/api/mappings/', ''));
        const parts = rawParam.split('/');
        const email = parts[0].toLowerCase().trim();
        const clientId = parts[1] ? parts[1].trim() : '*';

        await env.DB.prepare('DELETE FROM user_mappings WHERE email = ? AND client_id = ?')
          .bind(email, clientId)
          .run();

        return Response.json({ success: true });
      }

      return new Response(renderAdminConsoleHtml(accessUserEmail, env.ADMIN_ROUTE_PATH), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    return new Response('Not Found', { status: 404 });
  }
};
