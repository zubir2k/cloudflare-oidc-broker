import { UpstreamProvider, UpstreamUser } from './types';

export class GoogleProvider implements UpstreamProvider {
  readonly name = 'google';

  buildAuthUrl({ clientId, redirectUri, state }: { clientId: string; redirectUri: string; state: string }): string {
    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('state', state);
    url.searchParams.set('access_type', 'online');
    url.searchParams.set('prompt', 'select_account');
    return url.toString();
  }

  async exchangeCode({ code, clientId, clientSecret, redirectUri }: {
    code: string; clientId: string; clientSecret: string; redirectUri: string;
  }): Promise<UpstreamUser> {
    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, grant_type: 'authorization_code' })
    });
    if (!tokenResp.ok) throw new Error(`Google token exchange failed: ${tokenResp.status}`);
    const { access_token } = await tokenResp.json() as { access_token: string };

    const userResp = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    if (!userResp.ok) throw new Error(`Google userinfo failed: ${userResp.status}`);
    const u = await userResp.json() as { sub: string; email: string; email_verified: boolean; name?: string };

    return { sub: u.sub, email: u.email.toLowerCase(), email_verified: u.email_verified, name: u.name };
  }
}
