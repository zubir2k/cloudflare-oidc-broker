// Central provider registry — import each provider file to trigger self-registration.
// To add a new provider: create its .ts file, call register() at the bottom, import it here.
import './google';
import './microsoft';
import './github';
import './apple';

export { UpstreamProvider } from './types';
export type { UpstreamUser } from './types';
export { getProvider, getProviderCredentials, getRegisteredProviders } from './registry';
export type { ProviderCredentials } from './registry';