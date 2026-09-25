function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export async function verifyPkce(verifier: string, challenge: string, method: string): Promise<boolean> {
  // Fail closed: require explicit verifier, challenge, and method
  if (!verifier || !challenge || !method) {
    return false;
  }

  // Reject 'plain' or any algorithm other than S256 (OAuth 2.1 compliance)
  if (method !== 'S256') {
    return false;
  }

  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const computedChallenge = bufferToBase64Url(digest);
  return computedChallenge === challenge;
}