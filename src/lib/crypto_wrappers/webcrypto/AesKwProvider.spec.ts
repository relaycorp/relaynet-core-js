import { Crypto } from '@peculiar/webcrypto';
import { AesKwProvider as IAesKwProvider } from 'webcrypto-core';
import { arrayBufferFrom } from '../../_test_utils';

import { AesKwProvider } from './AesKwProvider';

const nodejsCrypto = new Crypto();

const algorithm: AesKeyGenParams = { name: 'AES-KW', length: 128 };
// tslint:disable-next-line:readonly-array
const keyUsages: KeyUsage[] = ['wrapKey', 'unwrapKey'];

let cryptoKey: CryptoKey;
beforeAll(async () => {
  cryptoKey = (await nodejsCrypto.subtle.generateKey(algorithm, true, keyUsages)) as CryptoKey;
});

describe('onGenerateKey', () => {
  test('Method should proxy original provider', async () => {
    const originalProvider = new MockAesKwProvider();
    originalProvider.onGenerateKey.mockResolvedValue(cryptoKey);
    const provider = new AesKwProvider(originalProvider);

    const generatedKey = await provider.onGenerateKey(algorithm, true, keyUsages);

    expect(generatedKey).toBe(cryptoKey);
    expect(originalProvider.onGenerateKey).toBeCalledWith(algorithm, true, keyUsages);
  });
});

describe('onExportKey', () => {
  test('Method should proxy original provider', async () => {
    const cryptoKeySerialized = arrayBufferFrom('this is the key, serialized');
    const originalProvider = new MockAesKwProvider();
    originalProvider.onExportKey.mockResolvedValue(cryptoKeySerialized);
    const provider = new AesKwProvider(originalProvider);
    const keyFormat = 'raw';

    const exportedKey = await provider.onExportKey(keyFormat, cryptoKey);

    expect(exportedKey).toBe(cryptoKeySerialized);
    expect(originalProvider.onExportKey).toBeCalledWith(keyFormat, cryptoKey);
  });
});

describe('onImportKey', () => {
  test('Method should proxy original provider', async () => {
    const originalProvider = new MockAesKwProvider();
    originalProvider.onImportKey.mockResolvedValue(cryptoKey);
    const provider = new AesKwProvider(originalProvider);
    const keyFormat = 'raw';
    const cryptoKeySerialized = arrayBufferFrom('this is the key, serialized');

    const exportedKey = await provider.onImportKey(
      keyFormat,
      cryptoKeySerialized,
      algorithm,
      true,
      keyUsages,
    );

    expect(exportedKey).toBe(cryptoKey);
    expect(originalProvider.onImportKey).toBeCalledWith(
      keyFormat,
      cryptoKeySerialized,
      algorithm,
      true,
      keyUsages,
    );
  });
});

describe('onEncrypt', () => {
  test.todo('Pure JS implementation should be used');

  test.todo('Ciphertext should be decryptable with Node.js');
});

describe('onDecrypt', () => {
  test.todo('Pure JS implementation should be used');

  test.todo('Ciphertext produced with Node.js should be decryptable');
});

class MockAesKwProvider extends IAesKwProvider {
  public readonly onGenerateKey = jest.fn();
  public readonly onExportKey = jest.fn();
  public readonly onImportKey = jest.fn();
}
