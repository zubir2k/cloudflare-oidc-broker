export interface Env {
  DB: D1Database;
  SESSIONS_KV: KVNamespace;
  ADMIN_ROUTE_PATH: string;

  // Per-provider upstream OAuth credentials (set only the providers you use)
  // Secrets set via: npx wrangler secret put <NAME>
  UPSTREAM_GOOGLE_CLIENT_ID?: string;
  UPSTREAM_GOOGLE_CLIENT_SECRET?: string;

  UPSTREAM_MICROSOFT_CLIENT_ID?: string;
  UPSTREAM_MICROSOFT_CLIENT_SECRET?: string;
  UPSTREAM_MICROSOFT_TENANT?: string;          // tenant ID or 'common' (default: 'common')

  UPSTREAM_GITHUB_CLIENT_ID?: string;
  UPSTREAM_GITHUB_CLIENT_SECRET?: string;

  UPSTREAM_APPLE_CLIENT_ID?: string;
  UPSTREAM_APPLE_CLIENT_SECRET?: string;       // .p8 PEM key content
  UPSTREAM_APPLE_TEAM_ID?: string;
  UPSTREAM_APPLE_KEY_ID?: string;

  // Admin console (Cloudflare Zero Trust)
  CF_ACCESS_TEAM_NAME: string;
  CF_ACCESS_AUD: string;
  ADMIN_API_TOKEN?: string;

  // Broker signing key (RS256 private JWK).
  // The public key is derived from this at runtime — no separate public key secret needed.
  BROKER_PRIVATE_KEY_JWK: string;
}

export interface ClientRecord {
  client_id: string;
  client_name: string;
  client_secret: string | null;
  redirect_uris: string;               // JSON string
  provider: string;                    // google | microsoft | github | apple
  require_pkce: number;                // 1 = S256 mandatory, 0 = exempt
  is_active: number;
  created_at?: string;
}

export interface UserMappingRecord {
  id: number;
  email: string;
  client_id: string;
  google_sub: string | null;           // stores any upstream provider sub (named for backwards compat)
  username: string;
  display_name: string | null;
  is_active: number;
  last_login: string | null;
  created_at?: string;
}

export interface BrokerSession {
  clientId: string;
  redirectUri: string;
  state: string;
  nonce: string;
  requirePkce: boolean;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  responseMode: 'query' | 'form_post';
  authTime?: number;
}

export interface DownstreamAuthCode {
  clientId: string;
  sub: string;
  email: string;
  emailVerified: boolean;
  username: string;
  name: string;
  nonce?: string;
  requirePkce: boolean;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  authTime?: number;
}
