import { UpstreamProvider, UpstreamUser } from './types';

// GitHub is OAuth2 only (not OIDC). Email requires a separate API call
// because GitHub users can hide their email from the basic /user endpoint.
export class GitHubProvider implements UpstreamProvider {
  readonly name = 'github';

  buildAuthUrl({ clientId, redirectUri, state }: { clientId: string; redirectUri: string; state: string }): string {
    const url = new URL('https://github.com/login/oauth/authorize');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', 'read:user user:email');
    url.searchParams.set('state', state);
    return url.toString();
  }

  async exchangeCode({ code, clientId, clientSecret, redirectUri }: {
    code: string; clientId: string; clientSecret: string; redirectUri: string;
  }): Promise<UpstreamUser> {
    // Step 1: exchange code for access token
    const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({ code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri })
    });
    if (!tokenResp.ok) throw new Error(`GitHub token exchange failed: ${tokenResp.status}`);
    const { access_token } = await tokenResp.json() as { access_token: string };

    const headers = { Authorization: `Bearer ${access_token}`, Accept: 'application/json', 'User-Agent': 'cloudflare-oidc-broker' };

    // Step 2: get user profile (id, login, name)
    const userResp = await fetch('https://api.github.com/user', { headers });
    if (!userResp.ok) throw new Error(`GitHub user fetch failed: ${userResp.status}`);
    const u = await userResp.json() as { id: number; login: string; name?: string; email?: string };

    // Step 3: get verified primary email (may not be in /user if user hid it)
    let email = u.email?.toLowerCase() || '';
    if (!email) {
      const emailsResp = await fetch('https://api.github.com/user/emails', { headers });
      if (emailsResp.ok) {
        const emails = await emailsResp.json() as { email: string; primary: boolean; verified: boolean }[];
        const primary = emails.find(e => e.primary && e.verified);
        email = primary?.email.toLowerCase() || '';
      }
    }
    if (!email) throw new Error('GitHub: no verified primary email found');

    return {
      sub: `github:${u.id}`,   // Namespace to avoid collision with other providers
      email,
      email_verified: true,     // GitHub only returns verified emails
      name: u.name || u.login
    };
  }
}
