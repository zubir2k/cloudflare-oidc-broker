// Apple Sign In quirks:
// 1. No userinfo endpoint — user claims are inside the id_token JWT
// 2. Client secret must be a signed JWT (not a static string)
// 3. Apple only sends name/email in the FIRST login — store them on first use
// 4. UPSTREAM_APPLE_TEAM_ID and UPSTREAM_APPLE_KEY_ID are required extras
//
// UPSTREAM_APPLE_CLIENT_SECRET = the PEM private key (.p8 file content)
// UPSTREAM_APPLE_TEAM_ID       = your Apple Developer Team ID
// UPSTREAM_APPLE_KEY_ID        = the Key ID of your Sign in with Apple private key

import { SignJWT, jwtVerify, createRemoteJWKSet } from 'jose';
import { UpstreamProvider, UpstreamUser } from './types';
import { register } from './registry';

export interface AppleEnv {
  UPSTREAM_APPLE_CLIENT_ID?: string;
  UPSTREAM_APPLE_CLIENT_SECRET?: string;
  UPSTREAM_APPLE_TEAM_ID?: string;
  UPSTREAM_APPLE_KEY_ID?: string;
}

export class AppleProvider implements UpstreamProvider {
  readonly name = 'apple';
  readonly issuer = 'https://appleid.apple.com';
  private teamId: string;
  private keyId: string;

  constructor(teamId: string, keyId: string) {
    this.teamId = teamId;
    this.keyId = keyId;
  }

  buildAuthUrl({ clientId, redirectUri, state, nonce }: { clientId: string; redirectUri: string; state: string; nonce: string }): string {
    const url = new URL('https://appleid.apple.com/auth/authorize');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'name email');
    url.searchParams.set('response_mode', 'form_post');
    url.searchParams.set('state', state);
    return url.toString();
  }

  private async buildClientSecret(clientId: string, pemKey: string): Promise<string> {
    const cleanedPem = pemKey
      .replace(/-----BEGIN PRIVATE KEY-----/, '')
      .replace(/-----END PRIVATE KEY-----/, '')
      .replace(/\s/g, '');
    const keyBytes = Uint8Array.from(atob(cleanedPem), c => c.charCodeAt(0));
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      keyBytes.buffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', kid: this.keyId })
      .setIssuer(this.teamId)
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .setAudience('https://appleid.apple.com')
      .setSubject(clientId)
      .sign(privateKey);
  }

  async exchangeCode({ code, clientId, clientSecret, redirectUri, expectedNonce }: {
    code: string; clientId: string; clientSecret: string; redirectUri: string; expectedNonce: string;
  }): Promise<UpstreamUser> {
    const appleClientSecret = await this.buildClientSecret(clientId, clientSecret);

    const tokenResp = await fetch('https://appleid.apple.com/auth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: appleClientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
      })
    });
    if (!tokenResp.ok) throw new Error(`Apple token exchange failed: ${tokenResp.status}`);
    const { id_token } = await tokenResp.json() as { id_token: string };

    const JWKS = createRemoteJWKSet(new URL('https://appleid.apple.com/auth/keys'));
    const { payload } = await jwtVerify(id_token, JWKS, {
      issuer: this.issuer,
      audience: clientId
    });

    const email = (payload.email as string | undefined)?.toLowerCase();
    if (!email) throw new Error('Apple: no email in id_token');

    return {
      sub: payload.sub as string,
      email,
      email_verified: !!(payload.email_verified),
      name: undefined
    };
  }
}

register('apple', {
  label: 'Apple',
  isReady: (env: any) => !!(env.UPSTREAM_APPLE_CLIENT_ID && env.UPSTREAM_APPLE_CLIENT_SECRET && env.UPSTREAM_APPLE_TEAM_ID && env.UPSTREAM_APPLE_KEY_ID),
  create: (env: any) => {
    if (!env.UPSTREAM_APPLE_CLIENT_ID || !env.UPSTREAM_APPLE_CLIENT_SECRET)
      throw new Error('Apple provider requires UPSTREAM_APPLE_CLIENT_ID and UPSTREAM_APPLE_CLIENT_SECRET');
    if (!env.UPSTREAM_APPLE_TEAM_ID || !env.UPSTREAM_APPLE_KEY_ID)
      throw new Error('Apple provider requires UPSTREAM_APPLE_TEAM_ID and UPSTREAM_APPLE_KEY_ID');
    return new AppleProvider(env.UPSTREAM_APPLE_TEAM_ID, env.UPSTREAM_APPLE_KEY_ID);
  },
  credentials: (env: any) => ({
    clientId: env.UPSTREAM_APPLE_CLIENT_ID!,
    clientSecret: env.UPSTREAM_APPLE_CLIENT_SECRET!
  })
});