import { UpstreamProvider, UpstreamUser } from './types';
import { register } from './registry';

export interface DiscordEnv {
  UPSTREAM_DISCORD_CLIENT_ID?: string;
  UPSTREAM_DISCORD_CLIENT_SECRET?: string;
}

// Discord is OAuth2 only (not OIDC). The 'email' scope is strictly required 
// to receive the email and verified fields from the /users/@me endpoint.
export class DiscordProvider implements UpstreamProvider {
  readonly name = 'discord';
  readonly issuer = 'https://discord.com';

  buildAuthUrl({ clientId, redirectUri, state }: { clientId: string; redirectUri: string; state: string; nonce: string }): string {
    const url = new URL('https://discord.com/oauth2/authorize');
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', 'identify email');
    url.searchParams.set('state', state);
    return url.toString();
  }

  async exchangeCode({ code, clientId, clientSecret, redirectUri }: {
    code: string; clientId: string; clientSecret: string; redirectUri: string; expectedNonce: string;
  }): Promise<UpstreamUser> {
    // 1. Exchange code for access token
    // Discord requires application/x-www-form-urlencoded. JSON is rejected.
    const tokenResp = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ 
        grant_type: 'authorization_code',
        code, 
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri 
      })
    });
    
    if (!tokenResp.ok) {
      const errText = await tokenResp.text();
      throw new Error(`Discord token exchange failed: ${tokenResp.status} - ${errText}`);
    }
    
    const { access_token } = await tokenResp.json() as { access_token: string };

    // 2. Fetch user info
    const userResp = await fetch('https://discord.com/api/v10/users/@me', {
      headers: { 
        Authorization: `Bearer ${access_token}`,
        'User-Agent': 'private-oidc-broker' 
      }
    });
    
    if (!userResp.ok) {
      const errText = await userResp.text();
      throw new Error(`Discord user fetch failed: ${userResp.status} - ${errText}`);
    }
    
    const u = await userResp.json() as { 
      id: string; 
      username: string; 
      global_name?: string | null; 
      email?: string | null; 
      verified?: boolean;
    };

    if (!u.email) {
      throw new Error('Discord: no email found. Ensure the "email" scope is requested and the user has a verified email attached to their Discord account.');
    }

    return {
      sub: `discord:${u.id}`,
      email: u.email.toLowerCase(),
      email_verified: u.verified || false,
      name: u.global_name || u.username
    };
  }
}

register('discord', {
  label: 'Discord',
  isReady: (env: any) => !!(env.UPSTREAM_DISCORD_CLIENT_ID && env.UPSTREAM_DISCORD_CLIENT_SECRET),
  create: (env: any) => {
    if (!env.UPSTREAM_DISCORD_CLIENT_ID || !env.UPSTREAM_DISCORD_CLIENT_SECRET) {
      throw new Error('Discord provider requires UPSTREAM_DISCORD_CLIENT_ID and UPSTREAM_DISCORD_CLIENT_SECRET');
    }
    return new DiscordProvider();
  },
  credentials: (env: any) => ({
    clientId: env.UPSTREAM_DISCORD_CLIENT_ID!,
    clientSecret: env.UPSTREAM_DISCORD_CLIENT_SECRET!
  })
});