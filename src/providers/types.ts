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

  // Build the upstream authorization URL to redirect the browser to
  buildAuthUrl(params: {
    clientId: string;
    redirectUri: string;
    state: string;
    scopes?: string[];
  }): string;

  // Exchange an authorization code for normalized user info
  exchangeCode(params: {
    code: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
  }): Promise<UpstreamUser>;
}
