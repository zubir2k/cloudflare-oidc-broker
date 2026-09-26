import { Env, ClientRecord, UserMappingRecord, BrokerSession, DownstreamAuthCode } from './types';
import { getProvider, getProviderCredentials, getRegisteredProviders } from './providers';
import { getIssuer } from './utils/origin';
import { getOidcConfiguration, getJwks } from './utils/oidc';
import { verifyPkce } from './utils/pkce';
import { generateBrokerSub } from './utils/subHash';
import { mintDownstreamIdToken } from './utils/jwt';
import { verifyCloudflareAccess } from './utils/access';
import { parseClientCredentials } from './utils/clientAuth';
import { renderAccessDeniedHtml } from './views/errorPage';
import { renderAdminConsoleHtml } from './views/adminConsole';
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

// Inject global security headers (immutable-safe for Cloudflare Workers)
function addSecurityHeaders(response: Response): Response {
  const newHeaders = new Headers(response.headers);
  newHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  newHeaders.set('X-Content-Type-Options', 'nosniff');
  newHeaders.set('Referrer-Policy', 'no-referrer');
  
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  });
}

// Restrictive CORS (immutable-safe, never use '*' for sensitive endpoints)
function addCorsHeaders(response: Response, allowedOrigin?: string): Response {
  const newHeaders = new Headers(response.headers);
  if (allowedOrigin) {
    newHeaders.set('Access-Control-Allow-Origin', allowedOrigin);
  }
  newHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  newHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname.replace(/\/+$/, '');
    const issuer = getIssuer(request, env);

    // -------------------------------------------------------------
    // CORS Preflight Handler
    // -------------------------------------------------------------
    if (request.method === 'OPTIONS') {
      return addSecurityHeaders(new Response(null, { status: 204 }));
    }

    // -------------------------------------------------------------
    // 0. Favicon Handler (Emoji 🔐)
    // -------------------------------------------------------------
    if (pathname === '/favicon.ico') {
      const emojiFavicon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y="80" font-size="80">🔐</text></svg>';
      return addSecurityHeaders(new Response(emojiFavicon, {
        headers: {
          'Content-Type': 'image/svg+xml',
          'Cache-Control': 'public, max-age=86400'
        }
      }));
    }

    // -------------------------------------------------------------
    // 1. OIDC Discovery Document
    // -------------------------------------------------------------
    if (pathname === '/.well-known/openid-configuration') {
      return addSecurityHeaders(Response.json(getOidcConfiguration(issuer)));
    }

    // -------------------------------------------------------------
    // 2. JWKS Public Keys
    // -------------------------------------------------------------
    if (pathname === '/.well-known/jwks.json') {
      return addSecurityHeaders(await getJwks(env));
    }

    // -------------------------------------------------------------
    // 3. Downstream Authorization -> Redirect to Upstream Provider
    // -------------------------------------------------------------
    if (pathname === '/authorize') {
      // RFC 9101 signed request objects are not supported.
      // Reject any request carrying a 'request' parameter to prevent forged claims.
      if (url.searchParams.has('request') || url.searchParams.has('request_uri')) {
        return addSecurityHeaders(Response.json(
          { error: 'invalid_request', error_description: 'request objects are not supported' },
          { status: 400 }
        ));
      }
      const requestClaims = {};
      const getParam = (key: string) => requestClaims[key] !== undefined ? requestClaims[key] : url.searchParams.get(key);

      const responseType = getParam('response_type');
      if (responseType !== 'code') {
        return addSecurityHeaders(Response.json({
          error: 'unsupported_response_type',
          error_description: 'Only authorization code flow (response_type=code) is supported.'
        }, { status: 400 }));
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
        return addSecurityHeaders(Response.json({
          error: 'invalid_request',
          error_description: 'Missing client_id or redirect_uri'
        }, { status: 400 }));
      }

      const client = await env.DB.prepare('SELECT * FROM clients WHERE client_id = ? AND is_active = 1')
        .bind(clientId)
        .first<ClientRecord>();

      if (!client) {
        return addSecurityHeaders(Response.json({
          error: 'unauthorized_client',
          error_description: 'Unauthorized or inactive client_id'
        }, { status: 403 }));
      }

      const allowedUris: string[] = JSON.parse(client.redirect_uris || '[]');
      if (!allowedUris.includes(redirectUri)) {
        return addSecurityHeaders(Response.json({
          error: 'invalid_request',
          error_description: 'Unauthorized redirect_uri'
        }, { status: 400 }));
      }

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
            const sessionAccepted = maxAge !== undefined ? maxAgeSatisfied : hasSession;
            if (!sessionAccepted) {
              const errorUrl = new URL(redirectUri);
              errorUrl.searchParams.set('error', 'login_required');
              errorUrl.searchParams.set('error_description', 'User is not authenticated or session has expired');
              if (state) errorUrl.searchParams.set('state', state);
              return addSecurityHeaders(Response.redirect(errorUrl.toString(), 302));
            }
            sessionAuthTime = cookieAuthTime;
          } else if (maxAgeSatisfied) {
            sessionAuthTime = cookieAuthTime;
          }
        } catch {
          // Ignore cookie parse errors — treat as no session
        }
      } else if (prompt === 'none') {
        const errorUrl = new URL(redirectUri);
        errorUrl.searchParams.set('error', 'login_required');
        errorUrl.searchParams.set('error_description', 'User is not authenticated');
        if (state) errorUrl.searchParams.set('state', state);
        return addSecurityHeaders(Response.redirect(errorUrl.toString(), 302));
      }

      const requirePkce = client.require_pkce !== 0;
      if (requirePkce) {
        if (!codeChallenge || codeChallengeMethod !== 'S256') {
          return addSecurityHeaders(Response.json({
            error: 'invalid_request',
            error_description: 'code_challenge and code_challenge_method=S256 are required'
          }, { status: 400 }));
        }
      } else if (codeChallengeMethod && codeChallengeMethod !== 'S256') {
        return addSecurityHeaders(Response.json({
          error: 'invalid_request',
          error_description: 'Only S256 is supported for code_challenge_method'
        }, { status: 400 }));
      }

      if (responseMode !== 'query' && responseMode !== 'form_post') {
        return addSecurityHeaders(Response.json({
          error: 'invalid_request',
          error_description: 'Unsupported response_mode. Only query or form_post are supported.'
        }, { status: 400 }));
      }

      const brokerSessionId = crypto.randomUUID();
      const upstreamNonce = crypto.randomUUID(); // Generate nonce for upstream ID token validation
      
      const sessionData: BrokerSession = {
        clientId,
        redirectUri,
        state,
        nonce,
        requirePkce,
        codeChallenge,
        codeChallengeMethod,
        responseMode,
        authTime: sessionAuthTime,
        upstreamNonce
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
        state: brokerSessionId,
        nonce: upstreamNonce
      });

      return addSecurityHeaders(Response.redirect(upstreamAuthUrl, 302));
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
        return addSecurityHeaders(Response.json({
          error: 'invalid_request',
          error_description: 'Invalid callback parameters'
        }, { status: 400 }));
      }

      const sessionRaw = await env.SESSIONS_KV.get(`session:${brokerSessionId}`);
      if (!sessionRaw) {
        return addSecurityHeaders(Response.json({
          error: 'invalid_request',
          error_description: 'Session expired or invalid'
        }, { status: 403 }));
      }
      const session: BrokerSession = JSON.parse(sessionRaw);
      await env.SESSIONS_KV.delete(`session:${brokerSessionId}`);

      const sessionClient = await env.DB.prepare('SELECT provider FROM clients WHERE client_id = ? AND is_active = 1')
        .bind(session.clientId)
        .first<{ provider: string }>();
      if (!sessionClient) {
        return addSecurityHeaders(Response.json({
          error: 'unauthorized_client',
          error_description: 'Client no longer active'
        }, { status: 403 }));
      }

      const provider = getProvider(sessionClient.provider, env);
      const credentials = getProviderCredentials(sessionClient.provider, env);
      let upstreamUser: Awaited<ReturnType<typeof provider.exchangeCode>>;
      try {
        upstreamUser = await provider.exchangeCode({
          code,
          clientId: credentials.clientId,
          clientSecret: credentials.clientSecret,
          redirectUri: `${issuer}/callback`,
          expectedNonce: session.upstreamNonce // Validate upstream ID token nonce
        });
      } catch (err: any) {
        console.error('Upstream provider error:', err?.message);
        return addSecurityHeaders(Response.json({
          error: 'server_error',
          error_description: 'Upstream identity verification failed'
        }, { status: 502 }));
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
        return new Response(renderAccessDeniedHtml(upstreamUser.email, session.redirectUri), {
          status: 403,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache'
          }
        });
      }
	  
      await env.DB.prepare(
        'UPDATE user_mappings SET last_login = CURRENT_TIMESTAMP, google_sub = COALESCE(google_sub, ?) WHERE id = ?'
      )
        .bind(upstreamUser.sub, mappedUser.id)
        .run();

      // Generate isolated downstream sub to prevent cross-provider collision
      const brokerSub = await generateBrokerSub(
        provider.issuer,
        upstreamUser.sub,
        session.clientId
      );

      const authTime = session.authTime || Math.floor(Date.now() / 1000);
      const brokerCode = crypto.randomUUID();
      const codePayload: DownstreamAuthCode = {
        clientId: session.clientId,
        sub: brokerSub,
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
      }))}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=3600`;

      if (session.responseMode === 'form_post') {
        const error = url.searchParams.get('error');
        if (error) {
          const errorDescription = url.searchParams.get('error_description');
          try {
            const html = renderFormPostErrorHtml(session.redirectUri, error, errorDescription, session.state);
            return addSecurityHeaders(new Response(html, {
              status: 200,
              headers: {
                'Content-Type': 'text/html',
                'Cache-Control': 'no-store, no-cache, must-revalidate',
                'Pragma': 'no-cache',
                'Set-Cookie': sessionCookie
              }
            }));
          } catch (e: any) {
            return addSecurityHeaders(Response.json(
              { error: 'invalid_request', error_description: e.message },
              { status: 400 }
            ));
          }
        }

        try {
          const html = renderFormPostHtml(session.redirectUri, brokerCode, session.state);
          return addSecurityHeaders(new Response(html, {
            status: 200,
            headers: {
              'Content-Type': 'text/html',
              'Cache-Control': 'no-store, no-cache, must-revalidate',
              'Pragma': 'no-cache',
              'Set-Cookie': sessionCookie
            }
          }));
        } catch (e: any) {
          return addSecurityHeaders(Response.json(
            { error: 'invalid_request', error_description: e.message },
            { status: 400 }
          ));
        }
      }

      const targetUrl = new URL(session.redirectUri);
      targetUrl.searchParams.set('code', brokerCode);
      if (session.state) targetUrl.searchParams.set('state', session.state);

      return addSecurityHeaders(new Response(null, {
        status: 302,
        headers: {
          'Location': targetUrl.toString(),
          'Set-Cookie': sessionCookie
        }
      }));
    }

    // -------------------------------------------------------------
    // 5. Downstream Token Endpoint
    // -------------------------------------------------------------
    if (pathname === '/token') {
      // RFC 6749 §3.2: MUST reject non-POST methods
      if (request.method !== 'POST') {
        return addSecurityHeaders(new Response(null, { 
          status: 405, 
          headers: { 'Allow': 'POST' } 
        }));
      }

      // Helper to ensure ALL token responses (success and error) are uncached per RFC 6749 §5.1 & §5.2
      const tokenResponse = (body: any, status: number) => {
        return addSecurityHeaders(Response.json(body, { 
          status,
          headers: {
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache'
          }
        }));
      };

      const { clientId, clientSecret, code, codeVerifier, authMethod } = await parseClientCredentials(request);

      // RFC 6749 §2.3: Reject mixed auth methods
      if (authMethod === 'mixed') {
        return tokenResponse({
          error: 'invalid_request',
          error_description: 'Client must not use multiple authentication methods in a single request'
        }, 400);
      }

      if (!code || !clientId) {
        return tokenResponse({
          error: 'invalid_request',
          error_description: 'Missing code or client_id'
        }, 400);
      }

      const client = await env.DB.prepare('SELECT * FROM clients WHERE client_id = ? AND is_active = 1')
        .bind(clientId)
        .first<ClientRecord>();

      if (!client) {
        return tokenResponse({
          error: 'invalid_client',
          error_description: 'Client not found or inactive'
        }, 401);
      }

      if (client.client_secret && client.client_secret !== clientSecret) {
        return tokenResponse({
          error: 'invalid_client',
          error_description: 'Unauthorized client credentials'
        }, 401);
      }

      const authDataRaw = await env.SESSIONS_KV.get(`code:${code}`);
      if (!authDataRaw) {
        return tokenResponse({
          error: 'invalid_grant',
          error_description: 'Code expired or invalid'
        }, 400);
      }
      const authData: DownstreamAuthCode = JSON.parse(authDataRaw);
      await env.SESSIONS_KV.delete(`code:${code}`);

      if (authData.clientId !== clientId) {
        return tokenResponse({
          error: 'invalid_grant',
          error_description: 'Client mismatch'
        }, 400);
      }

      if (authData.requirePkce) {
        if (!authData.codeChallenge) {
          return tokenResponse({
            error: 'invalid_grant',
            error_description: 'PKCE code_challenge was not established for this session'
          }, 400);
        }
        if (!codeVerifier) {
          return tokenResponse({
            error: 'invalid_request',
            error_description: 'Missing code_verifier'
          }, 400);
        }
        const isPkceValid = await verifyPkce(codeVerifier, authData.codeChallenge, authData.codeChallengeMethod || 'S256');
        if (!isPkceValid) {
          return tokenResponse({
            error: 'invalid_grant',
            error_description: 'PKCE verification failed'
          }, 400);
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

      const userTokensKey = `user_tokens:${authData.email}`;
      const existingIndexRaw = await env.SESSIONS_KV.get(userTokensKey);
      const existingTokens: string[] = existingIndexRaw ? JSON.parse(existingIndexRaw) : [];
      existingTokens.push(accessToken);
      await env.SESSIONS_KV.put(userTokensKey, JSON.stringify(existingTokens), { expirationTtl: 3600 });

      // RFC 6749 §5.1: Success response
      return tokenResponse({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: idToken
      }, 200);
    }

    // -------------------------------------------------------------
    // 6. Userinfo Endpoint (OIDC Standard)
    // -------------------------------------------------------------
    if (pathname === '/userinfo') {
      const authHeader = request.headers.get('authorization') || '';
      const accessToken = authHeader.replace(/^Bearer\s+/i, '').trim();

      if (!accessToken) {
        return addSecurityHeaders(Response.json({
          error: 'unauthorized',
          error_description: 'Missing access token'
        }, { status: 401 }));
      }

      const cachedRaw = await env.SESSIONS_KV.get(`access_token:${accessToken}`);
      if (!cachedRaw) {
        return addSecurityHeaders(Response.json({
          error: 'invalid_token',
          error_description: 'Token expired or invalid'
        }, { status: 401 }));
      }

      const userData = JSON.parse(cachedRaw);
      return addSecurityHeaders(Response.json({
        sub: userData.sub,
        email: userData.email,
        email_verified: userData.emailVerified === true,
        username: userData.username,
        preferred_username: userData.username,
        name: userData.name
      }, {
        headers: {
          'Cache-Control': 'no-store, no-cache, must-revalidate',
          'Pragma': 'no-cache'
        }
      }));
    }

    // -------------------------------------------------------------
    // 7. Token Revocation Endpoint (RFC 7009)
    // -------------------------------------------------------------
    if (pathname === '/revoke' && request.method === 'POST') {
      const { clientId, clientSecret, token, authMethod } = await parseClientCredentials(request);

      if (authMethod === 'mixed') {
        return addSecurityHeaders(Response.json({
          error: 'invalid_request',
          error_description: 'Client must not use multiple authentication methods'
        }, { status: 400 }));
      }

      if (!token) {
        return addSecurityHeaders(Response.json({
          error: 'invalid_request',
          error_description: 'Missing token parameter'
        }, { status: 400 }));
      }

      if (clientId) {
        const client = await env.DB.prepare('SELECT * FROM clients WHERE client_id = ? AND is_active = 1')
          .bind(clientId)
          .first<ClientRecord>();

        if (!client || (client.client_secret && client.client_secret !== clientSecret)) {
          return addSecurityHeaders(Response.json({
            error: 'invalid_client',
            error_description: 'Unauthorized client credentials'
          }, { status: 401 }));
        }
      }

      await env.SESSIONS_KV.delete(`access_token:${token}`);
      return addSecurityHeaders(new Response(null, { status: 200 }));
    }

    // -------------------------------------------------------------
    // 8. Logout Endpoint (RP-Initiated Single Logout)
    // -------------------------------------------------------------
    if (pathname === '/logout') {
      const postLogoutRedirectUri = url.searchParams.get('post_logout_redirect_uri');
      const idTokenHint = url.searchParams.get('id_token_hint');

      let logoutEmail: string | undefined;

      if (idTokenHint) {
        try {
          const parts = idTokenHint.split('.');
          if (parts.length === 3) {
            const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
            logoutEmail = payload.email as string | undefined;
            console.log(`[Logout] Extracted email from id_token_hint: ${logoutEmail}`);
          }
        } catch (e) {
          console.warn('[Logout] Failed to parse id_token_hint:', e);
        }
      }

      if (!logoutEmail) {
        try {
          const logoutCookies = request.headers.get('Cookie') || '';
          const logoutSessionMatch = logoutCookies.match(/user_session=([^;]+)/);
          if (logoutSessionMatch) {
            const cookieData = JSON.parse(decodeURIComponent(logoutSessionMatch[1]));
            logoutEmail = cookieData.email as string | undefined;
            console.log(`[Logout] Extracted email from session cookie: ${logoutEmail}`);
          } else {
            console.warn('[Logout] No user_session cookie found in request.');
          }
        } catch (e) {
          console.warn('[Logout] Failed to parse session cookie:', e);
        }
      }

      if (logoutEmail) {
        const userTokensKey = `user_tokens:${logoutEmail}`;
        const indexRaw = await env.SESSIONS_KV.get(userTokensKey);
        if (indexRaw) {
          try {
            const tokenIds: string[] = JSON.parse(indexRaw);
            await Promise.all([
              ...tokenIds.map(id => env.SESSIONS_KV.delete(`access_token:${id}`)),
              env.SESSIONS_KV.delete(userTokensKey)
            ]);
            console.log(`[Logout] Successfully purged ${tokenIds.length} tokens for ${logoutEmail}`);
          } catch (e) {
            console.error('[Logout] Error purging user tokens from KV:', e);
          }
        } else {
          console.log(`[Logout] No KV index found for ${logoutEmail}. User may have already logged out or session expired.`);
        }
      } else {
        console.error('[Logout] CRITICAL: Could not identify user email. KV entries will NOT be purged. Ensure downstream app sends id_token_hint or browser sends cookies.');
      }

      const clearCookie = 'user_session=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0';

      if (postLogoutRedirectUri) {
        const allClients = await env.DB.prepare('SELECT redirect_uris FROM clients WHERE is_active = 1').all<{ redirect_uris: string }>();
        const allAllowedUris = allClients.results.flatMap(c => {
          try { return JSON.parse(c.redirect_uris) as string[]; } catch { return []; }
        });

        const getOrigin = (u: string) => { try { return new URL(u).origin; } catch { return ''; } };
        const requestedOrigin = getOrigin(postLogoutRedirectUri);
        const isAllowed = !!requestedOrigin && allAllowedUris.some(u => getOrigin(u) === requestedOrigin);

        if (!isAllowed) {
          return addSecurityHeaders(new Response('Invalid post_logout_redirect_uri: not registered for any active client.', { 
            status: 400,
            headers: { 'Cache-Control': 'no-store' }
          }));
        }

        return addSecurityHeaders(new Response(null, {
          status: 302,
          headers: {
            'Location': postLogoutRedirectUri,
            'Set-Cookie': clearCookie,
            'Cache-Control': 'no-store'
          }
        }));
      }

      return addSecurityHeaders(new Response('You have been logged out.', {
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Set-Cookie': clearCookie,
          'Cache-Control': 'no-store'
        }
      }));
    }

    // -------------------------------------------------------------
    // 9. Zero Trust Protected Admin Console & APIs
    // -------------------------------------------------------------
    if (pathname.startsWith(env.ADMIN_ROUTE_PATH)) {
      const cfAccessEmail = request.headers.get('Cf-Access-Authenticated-User-Email');
      const authHeader = request.headers.get('Authorization');
      const hasValidToken = !!(env.ADMIN_API_TOKEN && authHeader === `Bearer ${env.ADMIN_API_TOKEN}`);

      if (!cfAccessEmail && !hasValidToken) {
        return addSecurityHeaders(new Response('Unauthorized: Missing valid Cloudflare Access session or Admin API Token.', { status: 401 }));
      }

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
        return addSecurityHeaders(Response.json({
          clients: clients.results.map((c: any) => ({ ...c, redirect_uris: JSON.parse(c.redirect_uris || '[]') })),
          mappings: mappings.results
        }));
      }

      if (apiPath === '/api/providers' && request.method === 'GET') {
        return addSecurityHeaders(Response.json(getRegisteredProviders(env)));
      }

      if (apiPath === '/api/clients' && request.method === 'POST') {
        const b = (await request.json()) as any;

        if (!b.client_id || typeof b.client_id !== 'string' || !b.client_name || typeof b.client_name !== 'string') {
          return addSecurityHeaders(Response.json({ error: 'invalid_request', error_description: 'client_id and client_name are required strings' }, { status: 400 }));
        }
        if (!Array.isArray(b.redirect_uris) || b.redirect_uris.length === 0) {
          return addSecurityHeaders(Response.json({ error: 'invalid_request', error_description: 'redirect_uris must be a non-empty array' }, { status: 400 }));
        }

        let finalSecret = (b.client_secret || '').trim();
        if (!finalSecret) {
          finalSecret = generateSecureSecret(48);
          console.log(`[SECURITY] Auto-generated 48-char secret for client: ${b.client_id}`);
        } else if (finalSecret.length < 32) {
          return addSecurityHeaders(Response.json({
            error: 'invalid_request',
            error_description: 'Custom client_secret must be at least 32 characters long for security'
          }, { status: 400 }));
        }

        await env.DB.prepare('INSERT OR REPLACE INTO clients (client_id, client_name, client_secret, redirect_uris, provider, require_pkce, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)')
          .bind(b.client_id.trim(), b.client_name.trim(), finalSecret, JSON.stringify(b.redirect_uris), b.provider || 'google', b.require_pkce !== undefined ? (b.require_pkce ? 1 : 0) : 1, b.is_active ? 1 : 0)
          .run();
        return addSecurityHeaders(Response.json({ success: true }));
      }

      if (apiPath.startsWith('/api/clients/') && request.method === 'DELETE') {
        const id = decodeURIComponent(apiPath.replace('/api/clients/', ''));
        await env.DB.prepare('DELETE FROM clients WHERE client_id = ?').bind(id).run();
        return addSecurityHeaders(Response.json({ success: true }));
      }

      if (apiPath === '/api/mappings' && request.method === 'POST') {
        const b = (await request.json()) as any;

        if (!b.email || typeof b.email !== 'string') {
          return addSecurityHeaders(Response.json({ error: 'invalid_request', error_description: 'email is required' }, { status: 400 }));
        }
        if (!b.username || typeof b.username !== 'string') {
          return addSecurityHeaders(Response.json({ error: 'invalid_request', error_description: 'username is required' }, { status: 400 }));
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

        return addSecurityHeaders(Response.json({ success: true }));
      }

      if (apiPath.startsWith('/api/mappings/') && request.method === 'DELETE') {
        const rawParam = decodeURIComponent(apiPath.replace('/api/mappings/', ''));
        const parts = rawParam.split('/');
        const email = parts[0].toLowerCase().trim();
        const clientId = parts[1] ? parts[1].trim() : '*';

        await env.DB.prepare('DELETE FROM user_mappings WHERE email = ? AND client_id = ?')
          .bind(email, clientId)
          .run();

        return addSecurityHeaders(Response.json({ success: true }));
      }

      return addSecurityHeaders(new Response(renderAdminConsoleHtml(accessUserEmail, env.ADMIN_ROUTE_PATH), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      }));
    }

    return addSecurityHeaders(new Response('Not Found', { status: 404 }));
  }
};