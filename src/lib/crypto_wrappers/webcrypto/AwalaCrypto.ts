import { Crypto as BaseCrypto } from '@peculiar/webcrypto';
import { getCiphers } from 'crypto';
import { AesKwProvider, SubtleCrypto } from 'webcrypto-core';

import { AwalaAesKwProvider } from './AwalaAesKwProvider';

export class AwalaCrypto extends BaseCrypto {
  constructor() {
    super();

    const doesNodejsSupportAesKw = getCiphers().includes('id-aes128-wrap');
    if (!doesNodejsSupportAesKw) {
      // This must be running on Electron: https://github.com/relaycorp/relaynet-core-js/issues/367
      const providers = (this.subtle as SubtleCrypto).providers;
      const nodejsAesKwProvider = providers.get('AES-KW') as AesKwProvider;
      providers.set(new AwalaAesKwProvider(nodejsAesKwProvider));
    }
  }
}
