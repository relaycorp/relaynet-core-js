import { CryptoEngine, getEngine, type ICryptoEngine } from 'pkijs';
import { ProviderCrypto } from 'webcrypto-core';

import { PrivateKey } from './keys/PrivateKey';
import { AwalaCrypto } from './webcrypto/AwalaCrypto';

const ENGINE_BY_PROVIDER = new WeakMap<ProviderCrypto, CryptoEngine>();

export const NODE_ENGINE = new CryptoEngine({ crypto: new AwalaCrypto(), name: 'node' });

/**
 * Generate and cache PKI.js engine for specified private key.
 */
export function getEngineForPrivateKey(privateKey: PrivateKey | CryptoKey): ICryptoEngine {
  if (!(privateKey instanceof PrivateKey)) {
    return getEngine().crypto!;
  }

  const cachedEngine = ENGINE_BY_PROVIDER.get(privateKey.provider);
  if (cachedEngine) {
    return cachedEngine;
  }

  const crypto = new AwalaCrypto([privateKey.provider]);
  const engine = new CryptoEngine({ crypto });
  ENGINE_BY_PROVIDER.set(privateKey.provider, engine);
  return engine;
}
