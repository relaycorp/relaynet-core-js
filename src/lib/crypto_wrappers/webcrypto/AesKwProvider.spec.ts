import { Crypto } from '@peculiar/webcrypto';
import bufferToArray from 'buffer-to-arraybuffer';
import { AesKwProvider as BaseAesKwProvider, SubtleCrypto } from 'webcrypto-core';
import { arrayBufferFrom } from '../../_test_utils';

import { AesKwProvider } from './AesKwProvider';

const nodejsCrypto = new Crypto();
const nodejsAesKwProvider = (nodejsCrypto.subtle as SubtleCrypto).providers.get(
  'AES-KW',
) as BaseAesKwProvider;

const algorithm: AesKeyGenParams = { name: 'AES-KW', length: 128 };
// tslint:disable-next-line:readonly-array
const keyUsages: KeyUsage[] = ['wrapKey', 'unwrapKey'];

let cryptoKey: CryptoKey;
beforeAll(async () => {
  cryptoKey = (await nodejsCrypto.subtle.generateKey(algorithm, true, keyUsages)) as CryptoKey;
});

const unwrappedKeySerialized = bufferToArray(
  Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex'),
);

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
  test('Ciphertext should be decryptable with Node.js', async () => {
    const provider = new AesKwProvider(nodejsAesKwProvider);

    const wrappedKey = await provider.onEncrypt(algorithm, cryptoKey, unwrappedKeySerialized);

    const unwrappedKey = await nodejsCrypto.subtle.unwrapKey(
      'raw',
      wrappedKey,
      cryptoKey,
      algorithm,
      algorithm,
      true,
      keyUsages,
    );
    await expect(nodejsAesKwProvider.exportKey('raw', unwrappedKey)).resolves.toEqual(
      unwrappedKeySerialized,
    );
  });
});

describe('onDecrypt', () => {
  test('Ciphertext produced with Node.js should be decryptable', async () => {
    const provider = new AesKwProvider(nodejsAesKwProvider);
    const nodejsWrappedKey = await nodejsAesKwProvider.onEncrypt(
      algorithm,
      cryptoKey,
      unwrappedKeySerialized,
    );

    const unwrappedKey = await provider.onDecrypt(algorithm, cryptoKey, nodejsWrappedKey);

    expect(unwrappedKey).toEqual(unwrappedKeySerialized);
  });
});

class MockAesKwProvider extends BaseAesKwProvider {
  public readonly onGenerateKey = jest.fn();
  public readonly onExportKey = jest.fn();
  public readonly onImportKey = jest.fn();
}
