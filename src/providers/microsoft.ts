import { UpstreamProvider, UpstreamUser } from './types';

// Supports both single-tenant (a specific tenant ID) and multi-tenant ('common') flows.
// Set UPSTREAM_PROVIDER_TENANT=common for personal/multi-tenant, or a specific Azure tenant ID.
export class MicrosoftProvider implements UpstreamProvider {
  readonly name = 'microsoft';
  private tenant: string;

  constructor(tenant = 'common') {
    this.tenant = tenant;
  }

  buildAuthUrl({ clientId, redirectUri, state }: { clientId: string; redirectUri: string; state: string }): string {
    const url = new URL(`https://login.microsoftonline.com/${this.tenant}/oauth2/v2.0/authorize`);
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('state', state);
    url.searchParams.set('prompt', 'select_account');
    return url.toString();
  }

  async exchangeCode({ code, clientId, clientSecret, redirectUri }: {
    code: string; clientId: string; clientSecret: string; redirectUri: string;
  }): Promise<UpstreamUser> {
    const tokenResp = await fetch(`https://login.microsoftonline.com/${this.tenant}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, grant_type: 'authorization_code', scope: 'openid email profile' })
    });
    if (!tokenResp.ok) throw new Error(`Microsoft token exchange failed: ${tokenResp.status}`);
    const { access_token } = await tokenResp.json() as { access_token: string };

    const userResp = await fetch('https://graph.microsoft.com/oidc/userinfo', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    if (!userResp.ok) throw new Error(`Microsoft userinfo failed: ${userResp.status}`);
    const u = await userResp.json() as { sub: string; email?: string; preferred_username?: string; name?: string };

    // Microsoft may return email as preferred_username for work accounts
    const email = (u.email || u.preferred_username || '').toLowerCase();
    if (!email) throw new Error('Microsoft: no email returned from userinfo');

    return { sub: u.sub, email, email_verified: true, name: u.name };
  }
}
