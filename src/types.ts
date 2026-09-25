export interface Env {
  DB: D1Database;
  SESSIONS_KV: KVNamespace;
  ADMIN_ROUTE_PATH: string;
  ISSUER_URL?: string;                 // Optional explicit issuer URL (recommended for production)  

  // Admin console (Cloudflare Zero Trust)
  CF_ACCESS_TEAM_NAME: string;
  CF_ACCESS_AUD: string;
  ADMIN_API_TOKEN?: string;

  // Broker signing key (RS256 private JWK).
  // The public key is derived from this at runtime — no separate public key secret needed.
  BROKER_PRIVATE_KEY_JWK: string;

  // Dynamic provider credentials are defined and validated within each provider module.
  // TypeScript will allow access to them via index signature or casting.
  [key: string]: any;
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
  upstreamNonce: string;               // Nonce sent to upstream provider for ID token validation
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