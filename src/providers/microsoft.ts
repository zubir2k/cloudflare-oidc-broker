import { createRemoteJWKSet, jwtVerify } from 'jose';
import { UpstreamProvider, UpstreamUser } from './types';
import { register } from './registry';

export interface MicrosoftEnv {
  UPSTREAM_MICROSOFT_CLIENT_ID?: string;
  UPSTREAM_MICROSOFT_CLIENT_SECRET?: string;
  UPSTREAM_MICROSOFT_TENANT?: string;
}

// Supports both single-tenant (a specific tenant ID) and multi-tenant ('common') flows.
// Set UPSTREAM_MICROSOFT_TENANT=common for personal/multi-tenant, or a specific Azure tenant ID.
export class MicrosoftProvider implements UpstreamProvider {
  readonly name = 'microsoft';
  readonly tenant: string;
  readonly issuer: string;

  constructor(tenant = 'common') {
    this.tenant = tenant;
    this.issuer = `https://login.microsoftonline.com/${tenant}/v2.0`;
  }

  buildAuthUrl({ clientId, redirectUri, state, nonce }: { 
    clientId: string; redirectUri: string; state: string; nonce: string; 
  }): string {
    const url = new URL(`https://login.microsoftonline.com/${this.tenant}/oauth2/v2.0/authorize`);
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('prompt', 'select_account');
    return url.toString();
  }

  async exchangeCode({ code, clientId, clientSecret, redirectUri, expectedNonce }: {
    code: string; clientId: string; clientSecret: string; redirectUri: string; expectedNonce: string;
  }): Promise<UpstreamUser> {
    const tokenResp = await fetch(`https://login.microsoftonline.com/${this.tenant}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ 
        code, client_id: clientId, client_secret: clientSecret, 
        redirect_uri: redirectUri, grant_type: 'authorization_code', 
        scope: 'openid email profile' 
      })
    });
    if (!tokenResp.ok) throw new Error(`Microsoft token exchange failed: ${tokenResp.status}`);
    const tokenData = await tokenResp.json() as { id_token?: string };

    if (!tokenData.id_token) throw new Error('Microsoft: missing id_token');

    const jwksUri = `https://login.microsoftonline.com/${this.tenant}/discovery/v2.0/keys`;
    const JWKS = createRemoteJWKSet(new URL(jwksUri));

    const verifyOptions: any = {
      audience: clientId,
      maxTokenAge: 600,
    };
    if (this.tenant !== 'common') {
      verifyOptions.issuer = this.issuer;
    }

    const { payload } = await jwtVerify(tokenData.id_token, JWKS, verifyOptions);

    // Multi-tenant: manually verify issuer is a valid Microsoft tenant
    if (this.tenant === 'common') {
      const iss = payload.iss as string;
      if (!iss || !iss.startsWith('https://login.microsoftonline.com/')) {
        throw new Error('Microsoft: invalid issuer in id_token');
      }
    }

    if (payload.nonce !== expectedNonce) {
      throw new Error('Microsoft: nonce mismatch (possible replay attack)');
    }

    if (!payload.sub || typeof payload.sub !== 'string') {
      throw new Error('Microsoft: missing sub in id_token');
    }

    const email = ((payload.email || payload.preferred_username) as string | undefined)?.toLowerCase();
    if (!email) throw new Error('Microsoft: no email in id_token');

    return {
      sub: payload.sub,
      email,
      email_verified: true,
      name: (payload.name as string) || email
    };
  }
}

register('microsoft', {
  label: 'Microsoft',
  isReady: (env: any) => !!(env.UPSTREAM_MICROSOFT_CLIENT_ID && env.UPSTREAM_MICROSOFT_CLIENT_SECRET),
  create: (env: any) => {
    if (!env.UPSTREAM_MICROSOFT_CLIENT_ID || !env.UPSTREAM_MICROSOFT_CLIENT_SECRET)
      throw new Error('Microsoft provider requires UPSTREAM_MICROSOFT_CLIENT_ID and UPSTREAM_MICROSOFT_CLIENT_SECRET');
    return new MicrosoftProvider(env.UPSTREAM_MICROSOFT_TENANT || 'common');
  },
  credentials: (env: any) => ({
    clientId: env.UPSTREAM_MICROSOFT_CLIENT_ID!,
    clientSecret: env.UPSTREAM_MICROSOFT_CLIENT_SECRET!
  })
});