import { getCiphers } from 'crypto';
import { AesKwProvider as BaseAesKwProvider, SubtleCrypto } from 'webcrypto-core';

import { getMockInstance } from '../../_test_utils';
import { AwalaAesKwProvider } from './AwalaAesKwProvider';
import { AwalaCrypto } from './AwalaCrypto';

jest.mock('crypto');

const CIPHERS: readonly string[] = [
  'aes-128-cbc',
  'aes-128-cfb',
  'aes-128-ctr',
  'aes-128-ecb',
  'aes-128-gcm',
  'aes-128-ofb',
];

describe('Constructor', () => {
  test("Pure JavaScript AES-KW provider should be used if Node doesn't support cipher", () => {
    getMockInstance(getCiphers).mockReturnValue(CIPHERS);

    const crypto = new AwalaCrypto();

    const aesKwProvider = (crypto.subtle as SubtleCrypto).providers.get('AES-KW');
    expect(aesKwProvider).toBeInstanceOf(AwalaAesKwProvider);
  });

  test('Node.js AES-KW provider should be used if Node supports cipher', () => {
    getMockInstance(getCiphers).mockReturnValue([...CIPHERS, 'id-aes128-wrap']);

    const crypto = new AwalaCrypto();

    const aesKwProvider = (crypto.subtle as SubtleCrypto).providers.get('AES-KW');
    expect(aesKwProvider).toBeInstanceOf(BaseAesKwProvider);
    expect(aesKwProvider).not.toBeInstanceOf(AwalaAesKwProvider);
  });
});
