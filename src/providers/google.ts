import { createRemoteJWKSet, jwtVerify } from 'jose';
import { UpstreamProvider, UpstreamUser } from './types';
import { register } from './registry';

export interface GoogleEnv {
  UPSTREAM_GOOGLE_CLIENT_ID?: string;
  UPSTREAM_GOOGLE_CLIENT_SECRET?: string;
}

const GOOGLE_ISSUER = 'https://accounts.google.com';
const GOOGLE_JWKS = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));

export class GoogleProvider implements UpstreamProvider {
  readonly name = 'google';
  readonly issuer = GOOGLE_ISSUER;

  buildAuthUrl({ clientId, redirectUri, state, nonce }: { 
    clientId: string; redirectUri: string; state: string; nonce: string; 
  }): string {
    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('access_type', 'online');
    url.searchParams.set('prompt', 'select_account');
    return url.toString();
  }

  async exchangeCode({ code, clientId, clientSecret, redirectUri, expectedNonce }: {
    code: string; clientId: string; clientSecret: string; redirectUri: string; expectedNonce: string;
  }): Promise<UpstreamUser> {
    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ 
        code, client_id: clientId, client_secret: clientSecret, 
        redirect_uri: redirectUri, grant_type: 'authorization_code' 
      })
    });
    if (!tokenResp.ok) throw new Error(`Google token exchange failed: ${tokenResp.status}`);
    const tokenData = await tokenResp.json() as { id_token?: string };

    if (!tokenData.id_token) throw new Error('Google: missing id_token in response');

    // Cryptographically validate the upstream ID token
    const { payload } = await jwtVerify(tokenData.id_token, GOOGLE_JWKS, {
      issuer: GOOGLE_ISSUER,
      audience: clientId,
      maxTokenAge: 600, // 10 minutes skew tolerance
    });

    if (payload.nonce !== expectedNonce) {
      throw new Error('Google: nonce mismatch (possible replay attack)');
    }

    if (!payload.sub || typeof payload.sub !== 'string') {
      throw new Error('Google: missing sub in id_token');
    }

    const email = (payload.email as string | undefined)?.toLowerCase();
    if (!email) throw new Error('Google: missing email in id_token');

    return {
      sub: payload.sub,
      email,
      email_verified: payload.email_verified === true,
      name: (payload.name as string) || email
    };
  }
}

register('google', {
  label: 'Google',
  isReady: (env: any) => !!(env.UPSTREAM_GOOGLE_CLIENT_ID && env.UPSTREAM_GOOGLE_CLIENT_SECRET),
  create: (env: any) => {
    if (!env.UPSTREAM_GOOGLE_CLIENT_ID || !env.UPSTREAM_GOOGLE_CLIENT_SECRET)
      throw new Error('Google provider requires UPSTREAM_GOOGLE_CLIENT_ID and UPSTREAM_GOOGLE_CLIENT_SECRET');
    return new GoogleProvider();
  },
  credentials: (env: any) => ({
    clientId: env.UPSTREAM_GOOGLE_CLIENT_ID!,
    clientSecret: env.UPSTREAM_GOOGLE_CLIENT_SECRET!
  })
});