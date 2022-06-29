import { CryptoKey, ProviderCrypto } from 'webcrypto-core';

export class PrivateKey extends CryptoKey {
  constructor(public readonly provider: ProviderCrypto) {
    super();

    this.type = 'private';
  }
}
