export function parseRequestObjectClaims(requestParam: string): Record<string, any> {
  try {
    const parts = requestParam.split('.');
    if (parts.length === 3) {
      // Base64url decode the payload (parts[1])
      const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      const pad = base64.length % 4;
      const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
      const binary = atob(padded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return JSON.parse(new TextDecoder().decode(bytes));
    }
  } catch (e) {
    // Invalid request object, return empty
  }
  return {};
}