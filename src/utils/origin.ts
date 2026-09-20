export function getIssuer(request: Request): string {
  const url = new URL(request.url);
  // Respect reverse proxy or Cloudflare forwarding headers if present
  const proto = request.headers.get('x-forwarded-proto') || url.protocol.replace(':', '');
  const host = request.headers.get('x-forwarded-host') || url.host;
  return `${proto}://${host}`;
}