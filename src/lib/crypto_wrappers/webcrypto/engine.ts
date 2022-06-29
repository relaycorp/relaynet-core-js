import { CryptoEngine } from 'pkijs';
import { ProviderCrypto } from 'webcrypto-core';

import { PrivateKey } from '../PrivateKey';
import { AwalaCrypto } from './AwalaCrypto';

const ENGINE_BY_PROVIDER = new WeakMap<ProviderCrypto, CryptoEngine>();

/**
 * Generate and cache PKI.js engine for specified private key.
 */
export function getEngineForPrivateKey(
  privateKey: PrivateKey | CryptoKey,
): CryptoEngine | undefined {
  if (!(privateKey instanceof PrivateKey)) {
    return undefined;
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
