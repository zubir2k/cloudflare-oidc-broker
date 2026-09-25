// src/utils/origin.ts

/**
 * Resolves the canonical issuer URL for the OIDC broker.
 * 
 * Cloudflare Workers often receive requests internally over HTTP.
 * We explicitly force the protocol to HTTPS to ensure upstream providers
 * (like Google) and downstream clients (like Home Assistant) always
 * receive secure endpoints.
 */
export function getIssuer(request: Request): string {
  const url = new URL(request.url);
  
  // Force HTTPS protocol
  url.protocol = 'https:';
  
  return url.origin; // Returns 'https://id.zubir.tech'
}
