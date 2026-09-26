import { UpstreamProvider, UpstreamUser } from './types';
import { register } from './registry';

export interface GitHubEnv {
  UPSTREAM_GITHUB_CLIENT_ID?: string;
  UPSTREAM_GITHUB_CLIENT_SECRET?: string;
}

// GitHub is OAuth2 only (not OIDC). Email requires a separate API call
// because GitHub users can hide their email from the basic /user endpoint.
export class GitHubProvider implements UpstreamProvider {
  readonly name = 'github';
  readonly issuer = 'https://github.com';

  buildAuthUrl({ clientId, redirectUri, state, nonce }: { clientId: string; redirectUri: string; state: string; nonce: string }): string {
    const url = new URL('https://github.com/login/oauth/authorize');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', 'read:user user:email');
    url.searchParams.set('state', state);
    return url.toString();
  }

  async exchangeCode({ code, clientId, clientSecret, redirectUri, expectedNonce }: {
    code: string; clientId: string; clientSecret: string; redirectUri: string; expectedNonce: string;
  }): Promise<UpstreamUser> {
    const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({ code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri })
    });
    if (!tokenResp.ok) throw new Error(`GitHub token exchange failed: ${tokenResp.status}`);
    const { access_token } = await tokenResp.json() as { access_token: string };

    const headers = { Authorization: `Bearer ${access_token}`, Accept: 'application/json', 'User-Agent': 'cloudflare-oidc-broker' };

    const userResp = await fetch('https://api.github.com/user', { headers });
    if (!userResp.ok) throw new Error(`GitHub user fetch failed: ${userResp.status}`);
    const u = await userResp.json() as { id: number; login: string; name?: string };

    // Always fetch /user/emails — never trust u.email from /user (unverified public profile field).
    const emailsResp = await fetch('https://api.github.com/user/emails', { headers });
    if (!emailsResp.ok) throw new Error(`GitHub emails fetch failed: ${emailsResp.status}`);
    const emails = await emailsResp.json() as { email: string; primary: boolean; verified: boolean }[];
    const primaryVerified = emails.find(e => e.primary === true && e.verified === true);
    if (!primaryVerified) throw new Error('GitHub: no verified primary email found');

    return {
      sub: `github:${u.id}`,
      email: primaryVerified.email.toLowerCase(),
      email_verified: true,
      name: u.name || u.login
    };
  }
}

register('github', {
  label: 'GitHub',
  isReady: (env: any) => !!(env.UPSTREAM_GITHUB_CLIENT_ID && env.UPSTREAM_GITHUB_CLIENT_SECRET),
  create: (env: any) => {
    if (!env.UPSTREAM_GITHUB_CLIENT_ID || !env.UPSTREAM_GITHUB_CLIENT_SECRET)
      throw new Error('GitHub provider requires UPSTREAM_GITHUB_CLIENT_ID and UPSTREAM_GITHUB_CLIENT_SECRET');
    return new GitHubProvider();
  },
  credentials: (env: any) => ({
    clientId: env.UPSTREAM_GITHUB_CLIENT_ID!,
    clientSecret: env.UPSTREAM_GITHUB_CLIENT_SECRET!
  })
});