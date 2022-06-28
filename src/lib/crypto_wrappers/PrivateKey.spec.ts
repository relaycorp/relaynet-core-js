import { Crypto } from '@peculiar/webcrypto';

import { PrivateKey } from './PrivateKey';

describe('constructor', () => {
  const CRYPTO = new Crypto();

  test('Key type should be private', () => {
    const key = new PrivateKey(CRYPTO);

    expect(key.type).toEqual('private');
  });

  test('Crypto should be honoured', () => {
    const key = new PrivateKey(CRYPTO);

    expect(key.crypto).toEqual(CRYPTO);
  });
});
