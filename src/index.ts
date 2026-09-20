import { Env, ClientRecord, UserMappingRecord, BrokerSession, DownstreamAuthCode } from './types';
import { getProvider, getProviderCredentials } from './providers';
import { getIssuer } from './utils/origin';
import { getOidcConfiguration, getJwks } from './utils/oidc';
import { verifyPkce } from './utils/pkce';
import { mintDownstreamIdToken } from './utils/jwt';
import { verifyCloudflareAccess } from './utils/access';
import { renderAdminConsoleHtml } from './views/adminConsole';

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

// Helper function to inject CORS headers for OIDC API endpoints
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
      return getJwks(env);
    }

    // -------------------------------------------------------------
    // 3. Downstream Authorization -> Redirect to Upstream Provider
    // -------------------------------------------------------------
    if (pathname === '/authorize') {
      // Strict response_type validation (OIDC Basic OP requirement)
      const responseType = url.searchParams.get('response_type');
      if (responseType !== 'code') {
        return Response.json({ 
          error: 'unsupported_response_type', 
          error_description: 'Only authorization code flow (response_type=code) is supported.' 
        }, { status: 400 });
      }

      const clientId = url.searchParams.get('client_id');
      const redirectUri = url.searchParams.get('redirect_uri');
      const state = url.searchParams.get('state') || '';
      const nonce = url.searchParams.get('nonce') || '';
      const codeChallenge = url.searchParams.get('code_challenge') || '';
      const codeChallengeMethod = url.searchParams.get('code_challenge_method') || '';

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

      const brokerSessionId = crypto.randomUUID();
      const sessionData: BrokerSession = { clientId, redirectUri, state, nonce, requirePkce, codeChallenge, codeChallengeMethod };

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

      // App-scoped mapping with fallback to global '*'
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
        // No email leak - generic error message
        return Response.json({ 
          error: 'access_denied', 
          error_description: 'User is not authorized for this application' 
        }, { status: 403 });
      }

      await env.DB.prepare(
        'UPDATE user_mappings SET last_login = CURRENT_TIMESTAMP, google_sub = COALESCE(google_sub, ?) WHERE id = ?'
      )
        .bind(upstreamUser.sub, mappedUser.id)
        .run();

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
        codeChallengeMethod: session.codeChallengeMethod
      };

      await env.SESSIONS_KV.put(
        `code:${brokerCode}`,
        JSON.stringify(codePayload),
        { expirationTtl: 120 }
      );

      const targetUrl = new URL(session.redirectUri);
      targetUrl.searchParams.set('code', brokerCode);
      if (session.state) targetUrl.searchParams.set('state', session.state);

      return Response.redirect(targetUrl.toString(), 302);
    }

    // -------------------------------------------------------------
    // 5. Downstream Token Endpoint
    // -------------------------------------------------------------
    if (pathname === '/token' && request.method === 'POST') {
      const contentType = request.headers.get('content-type') || '';
      let code = '';
      let clientId = '';
      let clientSecret = '';
      let codeVerifier = '';

      if (contentType.includes('application/x-www-form-urlencoded')) {
        const text = await request.text();
        const params = new URLSearchParams(text);
        code = params.get('code') || '';
        clientId = params.get('client_id') || '';
        clientSecret = params.get('client_secret') || '';
        codeVerifier = params.get('code_verifier') || '';
      } else {
        const formData = await request.formData();
        code = (formData.get('code') as string) || '';
        clientId = (formData.get('client_id') as string) || '';
        clientSecret = (formData.get('client_secret') as string) || '';
        codeVerifier = (formData.get('code_verifier') as string) || '';
      }

      const authHeader = request.headers.get('authorization');
      if (authHeader && authHeader.startsWith('Basic ')) {
        const credentials = atob(authHeader.split(' ')[1]).split(':');
        clientId = clientId || credentials[0];
        clientSecret = clientSecret || credentials[1];
      }

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
        privateKeyJwk: env.BROKER_PRIVATE_KEY_JWK,
        publicKeyJwk: env.BROKER_PUBLIC_KEY_JWK
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
        }, {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      const cachedRaw = await env.SESSIONS_KV.get(`access_token:${accessToken}`);
      if (!cachedRaw) {
        return addCorsHeaders(Response.json({ 
          error: 'invalid_token', 
          error_description: 'Token expired or invalid' 
        }, {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }));
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
      const contentType = request.headers.get('content-type') || '';
      let token = '';
      let clientId = '';
      let clientSecret = '';

      if (contentType.includes('application/x-www-form-urlencoded')) {
        const text = await request.text();
        const params = new URLSearchParams(text);
        token = params.get('token') || '';
        clientId = params.get('client_id') || '';
        clientSecret = params.get('client_secret') || '';
      } else {
        const formData = await request.formData();
        token = (formData.get('token') as string) || '';
        clientId = (formData.get('client_id') as string) || '';
        clientSecret = (formData.get('client_secret') as string) || '';
      }

      const authHeader = request.headers.get('authorization');
      if (authHeader && authHeader.startsWith('Basic ')) {
        const credentials = atob(authHeader.split(' ')[1]).split(':');
        clientId = clientId || credentials[0];
        clientSecret = clientSecret || credentials[1];
      }

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

        return Response.redirect(postLogoutRedirectUri, 302);
      }

      return new Response('You have been logged out.', {
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    // -------------------------------------------------------------
    // 9. Zero Trust Protected Operations Console & APIs
    // -------------------------------------------------------------
    if (pathname.startsWith(env.ADMIN_ROUTE_PATH)) {
      const accessUser = await verifyCloudflareAccess(request, env);
      if (!accessUser) {
        return new Response('Unauthorized Access: Invalid or missing Cloudflare Access token.', { status: 401 });
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

      return new Response(renderAdminConsoleHtml(accessUser.email, env.ADMIN_ROUTE_PATH), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    return new Response('Not Found', { status: 404 });
  }
};