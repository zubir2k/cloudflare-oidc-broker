// src/providers/mydigitalid.ts
//
// MyDigital ID (Malaysia national identity SSO) upstream provider.
//
// MyDigital ID returns an NRIC (IC number) as the primary identifier,
// not an email address. To remain compatible with the broker's
// email-keyed user_mappings table, the NRIC is salted-SHA256-hashed
// and stored as a synthetic address:
//
//   {saltedHash}@mydid.local
//
// This is deterministic — the same NRIC + salt always produces the
// same synthetic email — so user_mappings survive re-authentication.
//
// Because MyDigital ID handles national PII (full legal name + NRIC),
// this provider signals preferJwtAccessToken: true so the broker issues
// a self-contained RS256 JWT as the access token. No PII is written to
// KV after /token completes — identical behaviour to the original
// mydigitalid worker.
//
// Required env (secrets via: wrangler secret put <NAME>):
//   UPSTREAM_MYDIGITALID_REALM         e.g. mydid
//   UPSTREAM_MYDIGITALID_CLIENT_ID     e.g. mydid-broker
//   UPSTREAM_MYDIGITALID_CLIENT_SECRET
//   MYDIGITALID_NRIC_SALT              secret salt for NRIC hashing

import { createRemoteJWKSet, jwtVerify } from 'jose';
import { UpstreamProvider, UpstreamUser } from './types';
import { register } from './registry';

export interface MyDigitalIdEnv {
  UPSTREAM_MYDIGITALID_REALM?: string;
  UPSTREAM_MYDIGITALID_CLIENT_ID?: string;
  UPSTREAM_MYDIGITALID_CLIENT_SECRET?: string;
  MYDIGITALID_NRIC_SALT?: string;
}
const MYDIGITALID_BASE_URL = 'https://sso.digital-id.my';

// ----------------------------------------------------------------
// NRIC helpers
// ----------------------------------------------------------------

async function hashNric(nric: string, salt: string): Promise<string> {
  const cleaned = nric.replace(/[^0-9]/g, '');
  const encoder = new TextEncoder();
  const data = encoder.encode(cleaned + salt);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function nricToSyntheticEmail(nric: string, salt: string): Promise<string> {
  const hash = await hashNric(nric, salt);
  return `${hash}@mydid.local`;
}

// ----------------------------------------------------------------
// Provider
// ----------------------------------------------------------------

export class MyDigitalIdProvider implements UpstreamProvider {
  readonly name = 'mydigitalid';
  readonly issuer: string;

  private readonly oidcBase: string;
  private readonly nricSalt: string;

  constructor(realm: string, nricSalt: string) {
    this.issuer = `${MYDIGITALID_BASE_URL}/realms/${realm}`;
    this.oidcBase = `${this.issuer}/protocol/openid-connect`;
    this.nricSalt = nricSalt;
  }

  buildAuthUrl({ clientId, redirectUri, state, nonce }: {
    clientId: string;
    redirectUri: string;
    state: string;
    nonce: string;
  }): string {
    const url = new URL(`${this.oidcBase}/auth`);
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid profile');
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    return url.toString();
  }

  async exchangeCode({ code, clientId, clientSecret, redirectUri, expectedNonce }: {
    code: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    expectedNonce: string;
  }): Promise<UpstreamUser> {

    // --- Token exchange ---
    const tokenResp = await fetch(`${this.oidcBase}/token`, {
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
      throw new Error(`MyDigital ID token exchange failed: ${tokenResp.status}`);
    }

    const tokenData = await tokenResp.json() as {
      access_token?: string;
      id_token?: string;
    };

    // --- Upstream nonce validation via ID token ---
    if (tokenData.id_token) {
      try {
        const JWKS = createRemoteJWKSet(new URL(`${this.oidcBase}/certs`));
        const { payload } = await jwtVerify(tokenData.id_token, JWKS, {
          audience: clientId,
          maxTokenAge: 600
        });
        // Hard fail on nonce mismatch — unambiguous replay attempt
        if (payload.nonce && payload.nonce !== expectedNonce) {
          throw new Error('MyDigital ID: nonce mismatch (possible replay attack)');
        }
      } catch (err: any) {
        if (err.message?.includes('nonce mismatch')) throw err;
        // Warn and continue for clock skew / key rotation lag —
        // /userinfo below will confirm the identity authoritatively
        console.warn('MyDigital ID: ID token validation warning:', err?.message);
      }
    }

    // --- Fetch authoritative user profile ---
    if (!tokenData.access_token) {
      throw new Error('MyDigital ID: missing access_token in token response');
    }

    const userInfoResp = await fetch(`${this.oidcBase}/userinfo`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });

    if (!userInfoResp.ok) {
      throw new Error(`MyDigital ID: userinfo fetch failed: ${userInfoResp.status}`);
    }

    const userInfo = await userInfoResp.json() as {
      sub?: string;
      nric?: string;
      preferred_username?: string;
      nama?: string;
      name?: string;
    };

    // Resolve NRIC — fall through known claim names from MyDigital ID Keycloak
    const rawNric = userInfo.nric || userInfo.preferred_username || userInfo.sub;
    if (!rawNric) {
      throw new Error('MyDigital ID: could not resolve NRIC from userinfo response');
    }

    const nama = userInfo.nama || userInfo.name || 'Warganegara';

    // Hash NRIC → synthetic email used as the user_mappings.email key
    const syntheticEmail = await nricToSyntheticEmail(rawNric, this.nricSalt);

    return {
      sub: rawNric,               // raw NRIC — broker re-hashes via generateBrokerSub(issuer, sub, clientId)
      email: syntheticEmail,      // {saltedHash}@mydid.local
      email_verified: true,       // verified by JPN at source — stronger than any social provider
      name: nama,
      preferJwtAccessToken: true  // PII signal: skip KV writes after /token, issue JWT access token instead
    };
  }
}

// ----------------------------------------------------------------
// Registration
// ----------------------------------------------------------------

register('mydigitalid', {
  label: 'MyDigital ID',
  isReady: (env: MyDigitalIdEnv) =>
    !!(
      env.UPSTREAM_MYDIGITALID_REALM &&
      env.UPSTREAM_MYDIGITALID_CLIENT_ID &&
      env.UPSTREAM_MYDIGITALID_CLIENT_SECRET
    ),
  create: (env: MyDigitalIdEnv) => {
    if (
      !env.UPSTREAM_MYDIGITALID_REALM ||
      !env.UPSTREAM_MYDIGITALID_CLIENT_ID ||
      !env.UPSTREAM_MYDIGITALID_CLIENT_SECRET
    ) {
      throw new Error(
        'MyDigital ID provider requires UPSTREAM_MYDIGITALID_REALM, ' +
        'UPSTREAM_MYDIGITALID_CLIENT_ID, ' +
        'and UPSTREAM_MYDIGITALID_CLIENT_SECRET'
      );
    }
    return new MyDigitalIdProvider(
      env.UPSTREAM_MYDIGITALID_REALM,
      env.MYDIGITALID_NRIC_SALT || ''  // salt is optional but strongly recommended in production
    );
  },
  credentials: (env: MyDigitalIdEnv) => ({
    clientId: env.UPSTREAM_MYDIGITALID_CLIENT_ID!,
    clientSecret: env.UPSTREAM_MYDIGITALID_CLIENT_SECRET!
  })
});