import bufferToArray from 'buffer-to-arraybuffer';
import { CryptoEngine } from 'pkijs';

import { generateRSAKeyPair } from './generation';
import { arrayBufferFrom } from '../../_test_utils';
import { MockRsaPssProvider } from '../webcrypto/_test_utils';
import { RsaPssPrivateKey } from './PrivateKey';
import {
  derDeserializeECDHPrivateKey,
  derDeserializeECDHPublicKey,
  derDeserializeRSAPrivateKey,
  derDeserializeRSAPublicKey,
  derSerializePrivateKey,
  derSerializePublicKey,
} from './serialisation';

describe('Key serializers', () => {
  let stubKeyPair: CryptoKeyPair;
  beforeAll(async () => {
    stubKeyPair = await generateRSAKeyPair();
  });

  const stubExportedKeyDer = arrayBufferFrom('Hey');
  const mockExportKey = jest.spyOn(CryptoEngine.prototype, 'exportKey');
  beforeEach(async () => {
    mockExportKey.mockReset();
    mockExportKey.mockResolvedValue(stubExportedKeyDer);
  });

  afterAll(() => {
    mockExportKey.mockRestore();
  });

  describe('derSerializePublicKey', () => {
    test('Public key should be converted to buffer', async () => {
      const publicKeyDer = await derSerializePublicKey(stubKeyPair.publicKey);

      expect(publicKeyDer).toEqual(Buffer.from(stubExportedKeyDer));

      expect(mockExportKey).toBeCalledTimes(1);
      expect(mockExportKey).toBeCalledWith('spki', stubKeyPair.publicKey);
    });

    test('Public key should be extracted first if input is PrivateKey', async () => {
      const provider = new MockRsaPssProvider();
      provider.onExportKey.mockResolvedValue(stubExportedKeyDer);
      const privateKey = new RsaPssPrivateKey('SHA-256', provider);

      await expect(derSerializePublicKey(privateKey)).resolves.toEqual(
        Buffer.from(stubExportedKeyDer),
      );

      expect(mockExportKey).not.toBeCalled();
    });
  });

  describe('derSerializePrivateKey', () => {
    test('derSerializePrivateKey should convert private key to buffer', async () => {
      const privateKeyDer = await derSerializePrivateKey(stubKeyPair.privateKey);

      expect(privateKeyDer).toEqual(Buffer.from(stubExportedKeyDer));

      expect(mockExportKey).toBeCalledTimes(1);
      expect(mockExportKey).toBeCalledWith('pkcs8', stubKeyPair.privateKey);
    });
  });
});

describe('Key deserializers', () => {
  const stubKeyDer = Buffer.from('Hey');
  const rsaAlgorithmOptions: RsaHashedImportParams = { name: 'RSA-PSS', hash: { name: 'SHA-256' } };
  const ecdhCurveName: NamedCurve = 'P-384';

  let stubKeyPair: CryptoKeyPair;
  beforeAll(async () => {
    stubKeyPair = await generateRSAKeyPair();
  });
  const mockImportKey = jest.spyOn(CryptoEngine.prototype, 'importKey');
  beforeEach(async () => {
    mockImportKey.mockClear();
  });

  afterAll(() => {
    mockImportKey.mockRestore();
  });

  test('derDeserializeRSAPublicKey should convert DER public key to RSA key', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);

    const publicKey = await derDeserializeRSAPublicKey(stubKeyDer, rsaAlgorithmOptions);

    expect(publicKey).toBe(stubKeyPair.publicKey);
    expect(mockImportKey).toBeCalledTimes(1);
    expect(mockImportKey).toBeCalledWith(
      'spki',
      bufferToArray(stubKeyDer),
      rsaAlgorithmOptions,
      true,
      ['verify'],
    );
  });

  test('derDeserializeRSAPublicKey should default to RSA-PSS with SHA-256', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);

    const publicKey = await derDeserializeRSAPublicKey(stubKeyDer);

    expect(publicKey).toBe(stubKeyPair.publicKey);
    expect(mockImportKey).toBeCalledTimes(1);
    expect(mockImportKey).toBeCalledWith(
      'spki',
      bufferToArray(stubKeyDer),
      rsaAlgorithmOptions,
      true,
      ['verify'],
    );
  });

  test('derDeserializeRSAPublicKey should accept an ArrayBuffer serialization', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);

    const keyDerArrayBuffer = arrayBufferFrom(stubKeyDer);
    const publicKey = await derDeserializeRSAPublicKey(keyDerArrayBuffer, rsaAlgorithmOptions);

    expect(publicKey).toBe(stubKeyPair.publicKey);
    expect(mockImportKey).toBeCalledTimes(1);
    expect(mockImportKey).toBeCalledWith('spki', keyDerArrayBuffer, rsaAlgorithmOptions, true, [
      'verify',
    ]);
  });

  test('derDeserializeRSAPrivateKey should convert DER private key to RSA key', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.privateKey);

    const privateKey = await derDeserializeRSAPrivateKey(stubKeyDer, rsaAlgorithmOptions);

    expect(privateKey).toBe(stubKeyPair.privateKey);
    expect(mockImportKey).toBeCalledTimes(1);
    expect(mockImportKey).toBeCalledWith(
      'pkcs8',
      bufferToArray(stubKeyDer),
      rsaAlgorithmOptions,
      true,
      ['sign'],
    );
  });

  test('derDeserializeRSAPrivateKey should default to RSA-PSS with SHA-256', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.privateKey);

    const privateKey = await derDeserializeRSAPrivateKey(stubKeyDer);

    expect(privateKey).toBe(stubKeyPair.privateKey);
    expect(mockImportKey).toBeCalledTimes(1);
    expect(mockImportKey).toBeCalledWith(
      'pkcs8',
      bufferToArray(stubKeyDer),
      rsaAlgorithmOptions,
      true,
      ['sign'],
    );
  });

  test('derDeserializeECDHPublicKey should convert DER public key to ECDH key', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);

    const publicKey = await derDeserializeECDHPublicKey(stubKeyDer, ecdhCurveName);

    expect(publicKey).toBe(stubKeyPair.publicKey);
    expect(mockImportKey).toBeCalledTimes(1);
    expect(mockImportKey).toBeCalledWith(
      'spki',
      bufferToArray(stubKeyDer),
      { name: 'ECDH', namedCurve: ecdhCurveName },
      true,
      [],
    );
  });

  test('derDeserializeECDHPublicKey should default to P-256', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);

    await derDeserializeECDHPublicKey(stubKeyDer);

    expect(mockImportKey).toBeCalledTimes(1);
    const algorithm = mockImportKey.mock.calls[0][2];
    expect(algorithm).toHaveProperty('namedCurve', 'P-256');
  });

  test('derDeserializeECDHPublicKey should accept an ArrayBuffer serialization', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);

    const publicKeyDerArrayBuffer = bufferToArray(stubKeyDer);
    const publicKey = await derDeserializeECDHPublicKey(publicKeyDerArrayBuffer, ecdhCurveName);

    expect(publicKey).toBe(stubKeyPair.publicKey);
    expect(mockImportKey).toBeCalledTimes(1);
    expect(mockImportKey).toBeCalledWith(
      'spki',
      publicKeyDerArrayBuffer,
      { name: 'ECDH', namedCurve: ecdhCurveName },
      true,
      [],
    );
  });

  test('derDeserializeECDHPrivateKey should convert DER private key to ECDH key', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.privateKey);

    const privateKey = await derDeserializeECDHPrivateKey(stubKeyDer, ecdhCurveName);

    expect(privateKey).toBe(stubKeyPair.privateKey);
    expect(mockImportKey).toBeCalledTimes(1);
    expect(mockImportKey).toBeCalledWith(
      'pkcs8',
      bufferToArray(stubKeyDer),
      { name: 'ECDH', namedCurve: ecdhCurveName },
      true,
      ['deriveBits', 'deriveKey'],
    );
  });

  test('derDeserializeECDHPrivateKey should default to P-256', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.privateKey);

    await derDeserializeECDHPrivateKey(stubKeyDer);

    expect(mockImportKey).toBeCalledTimes(1);
    const algorithm = mockImportKey.mock.calls[0][2];
    expect(algorithm).toHaveProperty('namedCurve', 'P-256');
  });
});
