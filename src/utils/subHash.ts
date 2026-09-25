// Generates a deterministic, provider-scoped, client-scoped sub claim
// that isolates upstream identities from downstream consumers.

export async function generateBrokerSub(
  upstreamIssuer: string,
  upstreamSub: string,
  downstreamClientId: string
): Promise<string> {
  const encoder = new TextEncoder();
  const input = `${upstreamIssuer}:${upstreamSub}:${downstreamClientId}`;
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}