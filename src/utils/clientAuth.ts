export async function parseClientCredentials(request: Request): Promise<{
  clientId: string | null;
  clientSecret: string | null;
  token?: string | null;
  code?: string | null;
  codeVerifier?: string | null;
}> {
  let clientId: string | null = null;
  let clientSecret: string | null = null;
  let token: string | null = null;
  let code: string | null = null;
  let codeVerifier: string | null = null;

  const contentType = request.headers.get('content-type') || '';

  // 1. Try parsing from body (form-urlencoded or multipart/form-data)
  if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
    try {
      const formData = await request.formData();
      clientId = formData.get('client_id') as string | null;
      clientSecret = formData.get('client_secret') as string | null;
      token = formData.get('token') as string | null;
      code = formData.get('code') as string | null;
      codeVerifier = formData.get('code_verifier') as string | null;
    } catch (e) {
      // Ignore body parsing errors, fall back to headers
    }
  }

  // 2. Try parsing from Authorization: Basic header
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Basic ')) {
    try {
      const base64Credentials = authHeader.substring(6);
      const decoded = atob(base64Credentials);
      const colonIndex = decoded.indexOf(':');
      
      if (colonIndex !== -1) {
        // Body takes precedence, so only use header values if body was empty
        clientId = clientId || decodeURIComponent(decoded.substring(0, colonIndex));
        clientSecret = clientSecret || decodeURIComponent(decoded.substring(colonIndex + 1));
      }
    } catch (e) {
      // Invalid base64, ignore
    }
  }

  return { clientId, clientSecret, token, code, codeVerifier };
}