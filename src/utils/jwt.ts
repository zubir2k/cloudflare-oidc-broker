import { SignJWT, importJWK } from 'jose';

interface MintTokenParams {
  sub: string;
  email: string;
  emailVerified: boolean;
  username: string;
  name: string;
  clientId: string;
  issuer: string;
  nonce?: string;
  authTime?: number;
  privateKeyJwk: string;
}

export async function mintDownstreamIdToken(params: MintTokenParams): Promise<string> {
  const privateKey = await importJWK(JSON.parse(params.privateKeyJwk), 'RS256');
  const privateJwk = JSON.parse(params.privateKeyJwk);
  const now = Math.floor(Date.now() / 1000);
  const tokenAuthTime = params.authTime || now;

  return new SignJWT({
    sub: params.sub,
    email: params.email,
    email_verified: params.emailVerified,
    username: params.username,
    preferred_username: params.username,
    name: params.name,
    auth_time: tokenAuthTime,
    ...(params.nonce ? { nonce: params.nonce } : {})
  })
    .setProtectedHeader({ alg: 'RS256', kid: privateJwk.kid })
    .setIssuer(params.issuer)
    .setAudience(params.clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(privateKey);
}