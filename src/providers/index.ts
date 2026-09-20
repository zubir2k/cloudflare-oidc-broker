import { UpstreamProvider } from './types';
import { GoogleProvider } from './google';
import { MicrosoftProvider } from './microsoft';
import { GitHubProvider } from './github';
import { AppleProvider } from './apple';
import { Env } from '../types';

export { UpstreamProvider };
export type { UpstreamUser } from './types';

export interface ProviderCredentials {
  clientId: string;
  clientSecret: string;
}

export function getProvider(providerName: string, env: Env): UpstreamProvider {
  const name = providerName.toLowerCase().trim();

  switch (name) {
    case 'google':
      if (!env.UPSTREAM_GOOGLE_CLIENT_ID || !env.UPSTREAM_GOOGLE_CLIENT_SECRET) {
        throw new Error('Google provider requires UPSTREAM_GOOGLE_CLIENT_ID and UPSTREAM_GOOGLE_CLIENT_SECRET');
      }
      return new GoogleProvider();

    case 'microsoft':
      if (!env.UPSTREAM_MICROSOFT_CLIENT_ID || !env.UPSTREAM_MICROSOFT_CLIENT_SECRET) {
        throw new Error('Microsoft provider requires UPSTREAM_MICROSOFT_CLIENT_ID and UPSTREAM_MICROSOFT_CLIENT_SECRET');
      }
      return new MicrosoftProvider(env.UPSTREAM_MICROSOFT_TENANT || 'common');

    case 'github':
      if (!env.UPSTREAM_GITHUB_CLIENT_ID || !env.UPSTREAM_GITHUB_CLIENT_SECRET) {
        throw new Error('GitHub provider requires UPSTREAM_GITHUB_CLIENT_ID and UPSTREAM_GITHUB_CLIENT_SECRET');
      }
      return new GitHubProvider();

    case 'apple':
      if (!env.UPSTREAM_APPLE_CLIENT_ID || !env.UPSTREAM_APPLE_CLIENT_SECRET) {
        throw new Error('Apple provider requires UPSTREAM_APPLE_CLIENT_ID and UPSTREAM_APPLE_CLIENT_SECRET');
      }
      if (!env.UPSTREAM_APPLE_TEAM_ID || !env.UPSTREAM_APPLE_KEY_ID) {
        throw new Error('Apple provider requires UPSTREAM_APPLE_TEAM_ID and UPSTREAM_APPLE_KEY_ID');
      }
      return new AppleProvider(env.UPSTREAM_APPLE_TEAM_ID, env.UPSTREAM_APPLE_KEY_ID);

    default:
      throw new Error(`Unknown provider: "${name}". Supported: google, microsoft, github, apple`);
  }
}

export function getProviderCredentials(providerName: string, env: Env): ProviderCredentials {
  const name = providerName.toLowerCase().trim();

  switch (name) {
    case 'google':
      return { clientId: env.UPSTREAM_GOOGLE_CLIENT_ID!, clientSecret: env.UPSTREAM_GOOGLE_CLIENT_SECRET! };
    case 'microsoft':
      return { clientId: env.UPSTREAM_MICROSOFT_CLIENT_ID!, clientSecret: env.UPSTREAM_MICROSOFT_CLIENT_SECRET! };
    case 'github':
      return { clientId: env.UPSTREAM_GITHUB_CLIENT_ID!, clientSecret: env.UPSTREAM_GITHUB_CLIENT_SECRET! };
    case 'apple':
      return { clientId: env.UPSTREAM_APPLE_CLIENT_ID!, clientSecret: env.UPSTREAM_APPLE_CLIENT_SECRET! };
    default:
      throw new Error(`Unknown provider: "${name}"`);
  }
}
