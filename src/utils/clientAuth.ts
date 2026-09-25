export async function parseClientCredentials(request: Request): Promise<{
  clientId: string | null;
  clientSecret: string | null;
  token?: string | null;
  code?: string | null;
  codeVerifier?: string | null;
  authMethod: 'body' | 'basic' | 'none' | 'mixed';
}> {
  let bodyClientId: string | null = null;
  let bodySecret: string | null = null;
  let basicClientId: string | null = null;
  let basicSecret: string | null = null;
  let token: string | null = null;
  let code: string | null = null;
  let codeVerifier: string | null = null;

  const contentType = request.headers.get('content-type') || '';

  // 1. Try parsing from body (form-urlencoded or multipart/form-data)
  if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
    try {
      const formData = await request.formData();
      bodyClientId = formData.get('client_id') as string | null;
      bodySecret = formData.get('client_secret') as string | null;
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
        basicClientId = decodeURIComponent(decoded.substring(0, colonIndex));
        basicSecret = decodeURIComponent(decoded.substring(colonIndex + 1));
      }
    } catch (e) {
      // Invalid base64, ignore
    }
  }

  // 3. Detect dual-method usage (RFC 6749 §2.3 violation)
  const hasBodyAuth = bodyClientId !== null;
  const hasBasicAuth = basicClientId !== null;
  let authMethod: 'body' | 'basic' | 'none' | 'mixed' = 'none';

  if (hasBodyAuth && hasBasicAuth) {
    authMethod = 'mixed';
  } else if (hasBodyAuth) {
    authMethod = 'body';
  } else if (hasBasicAuth) {
    authMethod = 'basic';
  }

  return { 
    clientId: bodyClientId ?? basicClientId, 
    clientSecret: bodySecret ?? basicSecret, 
    token, 
    code, 
    codeVerifier, 
    authMethod 
  };
}