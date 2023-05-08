import { CryptoEngine, type ICryptoEngine } from 'pkijs';
import { ProviderCrypto } from 'webcrypto-core';

import { AwalaCrypto } from './webcrypto/AwalaCrypto';
import { CryptoKeyWithProvider } from './keys/CryptoKeyWithProvider';

const ENGINE_BY_PROVIDER = new WeakMap<ProviderCrypto, CryptoEngine>();

export const NODE_ENGINE = new CryptoEngine({ crypto: new AwalaCrypto(), name: 'node' });

/**
 * Generate and cache PKI.js engine for specified key.
 */
export function getEngineForKey(key: CryptoKey | CryptoKeyWithProvider): ICryptoEngine {
  const provider = (key as CryptoKeyWithProvider).provider as ProviderCrypto | undefined;
  if (!provider) {
    return NODE_ENGINE;
  }

  const cachedEngine = ENGINE_BY_PROVIDER.get(provider);
  if (cachedEngine) {
    return cachedEngine;
  }

  const crypto = new AwalaCrypto([provider]);
  const engine = new CryptoEngine({ crypto });
  ENGINE_BY_PROVIDER.set(provider, engine);
  return engine;
}
