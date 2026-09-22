import { Env } from '../types';

export function getOidcConfiguration(issuer: string) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    revocation_endpoint: `${issuer}/revoke`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    end_session_endpoint: `${issuer}/logout`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'email', 'profile'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'email', 'username', 'preferred_username', 'name'],
    code_challenge_methods_supported: ['S256'],
    request_parameter_supported: true
  };
}

export async function getJwks(env: Env): Promise<Response> {
  if (!env.BROKER_PRIVATE_KEY_JWK) {
    return new Response(JSON.stringify({ error: 'BROKER_PRIVATE_KEY_JWK is not configured' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    // Parse the private JWK
    const privateJwk = JSON.parse(env.BROKER_PRIVATE_KEY_JWK);

    // Construct the public JWK using only the public components of the private key.
    // This avoids the "non-extractable CryptoKey" error entirely.
    const publicJwk = {
      kty: privateJwk.kty,
      use: 'sig',
      alg: 'RS256',
      kid: privateJwk.kid,
      n:   privateJwk.n,
      e:   privateJwk.e
    };

    return Response.json({ keys: [publicJwk] });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: 'Failed to parse JWK', detail: err.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
