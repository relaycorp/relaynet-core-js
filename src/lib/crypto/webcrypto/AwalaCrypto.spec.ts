import { getCiphers } from 'crypto';
import { SubtleCrypto } from 'webcrypto-core';

import { getMockInstance } from '../../_test_utils';
import { MockAesKwProvider } from './_test_utils';
import { AwalaAesKwProvider } from './AwalaAesKwProvider';
import { AwalaCrypto } from './AwalaCrypto';

jest.mock('crypto', () => ({
  getCiphers: jest.fn().mockReturnValue([]),
}));

const CIPHERS: readonly string[] = [
  'aes-128-cbc',
  'aes-128-cfb',
  'aes-128-ctr',
  'aes-128-ecb',
  'aes-128-gcm',
  'aes-128-ofb',
];

beforeEach(() => {
  const mockGetCiphers = getMockInstance(getCiphers);
  mockGetCiphers.mockReset();
  mockGetCiphers.mockReturnValue(CIPHERS);
});

describe('Constructor', () => {
  test("Pure JavaScript AES-KW provider should be used if Node doesn't support cipher", () => {
    const crypto = new AwalaCrypto();

    const aesKwProvider = (crypto.subtle as SubtleCrypto).providers.get('AES-KW');
    expect(aesKwProvider).toBeInstanceOf(AwalaAesKwProvider);
  });

  test('Node.js AES-KW provider should be used if Node supports cipher', () => {
    getMockInstance(getCiphers).mockReturnValue([...CIPHERS, 'id-aes128-wrap']);

    const crypto = new AwalaCrypto();

    const aesKwProvider = (crypto.subtle as SubtleCrypto).providers.get('AES-KW');
    expect(aesKwProvider).toBeTruthy();
    expect(aesKwProvider).not.toBeInstanceOf(AwalaAesKwProvider);
  });

  test('Custom providers should be registered', () => {
    const providerName = 'COOL-PROVIDER';
    const customProvider = new (class extends MockAesKwProvider {
      override readonly name = providerName as any;
    })();
    const crypto = new AwalaCrypto([customProvider]);

    expect((crypto.subtle as SubtleCrypto).providers.get(providerName)).toBe(customProvider);
  });
});
