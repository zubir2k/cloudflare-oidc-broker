import { jwtVerify, createRemoteJWKSet } from 'jose';
import { Env } from '../types';

export async function verifyCloudflareAccess(request: Request, env: Env): Promise<{ email: string } | null> {
  const token = request.headers.get('Cf-Access-Jwt-Assertion');
  if (!token) return null;

  try {
    const certsUrl = new URL(`https://${env.CF_ACCESS_TEAM_NAME}.cloudflareaccess.com/cdn-cgi/access/certs`);
    const JWKS = createRemoteJWKSet(certsUrl);

    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://${env.CF_ACCESS_TEAM_NAME}.cloudflareaccess.com`,
      audience: env.CF_ACCESS_AUD,
    });

    return { email: payload.email as string };
  } catch (err) {
    console.error('Zero Trust verification failed:', err);
    return null;
  }
}