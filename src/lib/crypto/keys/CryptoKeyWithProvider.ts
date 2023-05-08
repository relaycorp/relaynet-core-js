import type { ProviderCrypto } from 'webcrypto-core';

export interface CryptoKeyWithProvider {
  readonly provider: ProviderCrypto;
}
