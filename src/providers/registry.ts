import { UpstreamProvider } from './types';

export interface ProviderCredentials {
  clientId: string;
  clientSecret: string;
}

export interface ProviderRegistration {
  // Human-readable label for the UI
  label: string;
  
  // Check if this provider has all required env vars configured
  isReady(env: any): boolean;

  // Factory: receives env and returns a ready provider instance.
  // Throws if required env vars are missing.
  create(env: any): UpstreamProvider;

  // Returns the clientId and clientSecret for this provider from env.
  credentials(env: any): ProviderCredentials;
}

// Central registry — each provider file calls register() to add itself.
const registry = new Map<string, ProviderRegistration>();

export function register(name: string, reg: ProviderRegistration): void {
  registry.set(name.toLowerCase(), reg);
}

export function getProvider(providerName: string, env: any): UpstreamProvider {
  const reg = registry.get(providerName.toLowerCase().trim());
  if (!reg) {
    throw new Error(
      `Unknown provider: "${providerName}". Registered: ${[...registry.keys()].join(', ')}`
    );
  }
  return reg.create(env);
}

export function getProviderCredentials(providerName: string, env: any): ProviderCredentials {
  const reg = registry.get(providerName.toLowerCase().trim());
  if (!reg) throw new Error(`Unknown provider: "${providerName}"`);
  return reg.credentials(env);
}

export interface ProviderMetadata {
  id: string;
  label: string;
  isReady: boolean;
}

// Returns all registered providers with their readiness status for the UI
export function getRegisteredProviders(env: any): ProviderMetadata[] {
  const result: ProviderMetadata[] = [];
  for (const [id, reg] of registry.entries()) {
    result.push({
      id,
      label: reg.label,
      isReady: reg.isReady(env)
    });
  }
  return result;
}