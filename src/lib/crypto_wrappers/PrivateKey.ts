import { CryptoKey } from 'webcrypto-core';

export class PrivateKey extends CryptoKey {
  constructor(public readonly crypto: Crypto) {
    super();

    this.type = 'private';
  }
}
