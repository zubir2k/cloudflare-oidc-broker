import { Env } from '../types';

/**
 * Resolves the canonical issuer URL for the OIDC broker.
 * Uses ISSUER_URL from env if set (recommended for production),
 * otherwise derives it from the incoming request.
 * ALWAYS forces HTTPS to prevent issuer mismatch errors.
 */
export function getIssuer(request: Request, env: Env): string {
  let origin: string;

  if (env.ISSUER_URL) {
    origin = env.ISSUER_URL.replace(/\/+$/, '');
  } else {
    const url = new URL(request.url);
    origin = url.origin;
  }

  // Force HTTPS to prevent http:// issuer mismatches
  if (origin.startsWith('http://')) {
    origin = 'https://' + origin.substring(7);
  } else if (!origin.startsWith('https://')) {
    origin = 'https://' + origin;
  }

  return origin;
}