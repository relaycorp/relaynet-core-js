import { CryptoEngine, getEngine, type ICryptoEngine } from 'pkijs';
import { ProviderCrypto } from 'webcrypto-core';

import { PrivateKey } from '../PrivateKey';
import { AwalaCrypto } from './AwalaCrypto';

const ENGINE_BY_PROVIDER = new WeakMap<ProviderCrypto, CryptoEngine>();

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
