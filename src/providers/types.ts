// Common normalized user info returned by every upstream provider
export interface UpstreamUser {
  sub: string;             // Unique ID from the upstream provider
  email: string;           // Lowercase email address
  email_verified: boolean;
  name?: string;
}

// Every upstream provider must implement this interface
export interface UpstreamProvider {
  readonly name: string;
  readonly issuer: string; // Issuer URL for ID token validation (e.g., 'https://accounts.google.com')

  // Build the upstream authorization URL to redirect the browser to
  buildAuthUrl(params: {
    clientId: string;
    redirectUri: string;
    state: string;
    nonce: string;         // Required for upstream ID token validation
    scopes?: string[];
  }): string;

  // Exchange an authorization code for normalized user info, validating the ID token
  exchangeCode(params: {
    code: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    expectedNonce: string; // Nonce to validate against the upstream ID token
  }): Promise<UpstreamUser>;
}