// tslint:disable:no-let
import bufferToArray from 'buffer-to-arraybuffer';
import { CryptoEngine } from 'pkijs';

import { expectBuffersToEqual } from '../_test_utils';
import {
  convertSignaturePrivateKeyToEncryption,
  derDeserializeECDHPrivateKey,
  derDeserializeECDHPublicKey,
  derDeserializeRSAPrivateKey,
  derDeserializeRSAPublicKey,
  derSerializePrivateKey,
  derSerializePublicKey,
  ECDHCurveName,
  generateECDHKeyPair,
  generateRSAKeyPair,
} from './keys';

describe('generateRsaKeyPair', () => {
  test('Keys should be RSA', async () => {
    const keyPair = await generateRSAKeyPair();

    expect(keyPair.publicKey.algorithm.name).toMatch(/^RSA-/);
    expect(keyPair.privateKey.algorithm.name).toMatch(/^RSA-/);
  });

  test('Keys should be extractable', async () => {
    const keyPair = await generateRSAKeyPair();

    expect(keyPair.publicKey.extractable).toBe(true);
    expect(keyPair.privateKey.extractable).toBe(true);
  });

  describe('Modulus', () => {
    test('Default modulus should be 2048', async () => {
      const keyPair = await generateRSAKeyPair();
      // @ts-ignore
      expect(keyPair.publicKey.algorithm.modulusLength).toBe(2048);
      // @ts-ignore
      expect(keyPair.privateKey.algorithm.modulusLength).toBe(2048);
    });

    test('Modulus > 2048 should be supported', async () => {
      const modulus = 3072;
      const keyPair = await generateRSAKeyPair({ modulus });
      // @ts-ignore
      expect(keyPair.publicKey.algorithm.modulusLength).toBe(modulus);
      // @ts-ignore
      expect(keyPair.privateKey.algorithm.modulusLength).toBe(modulus);
    });

    test('Modulus < 2048 should not supported', async () => {
      await expect(generateRSAKeyPair({ modulus: 1024 })).rejects.toThrow(
        'RSA modulus must be => 2048 per RS-018 (got 1024)',
      );
    });
  });

  describe('Hashing algorithm', () => {
    test('SHA-256 should be used by default', async () => {
      const keyPair = await generateRSAKeyPair();
      // @ts-ignore
      expect(keyPair.publicKey.algorithm.hash.name).toBe('SHA-256');
      // @ts-ignore
      expect(keyPair.privateKey.algorithm.hash.name).toBe('SHA-256');
    });

    ['SHA-384', 'SHA-512'].forEach(hashingAlgorithm => {
      test(`${hashingAlgorithm} should be supported`, async () => {
        const keyPair = await generateRSAKeyPair({ hashingAlgorithm });
        // @ts-ignore
        expect(keyPair.publicKey.algorithm.hash.name).toBe(hashingAlgorithm);
        // @ts-ignore
        expect(keyPair.privateKey.algorithm.hash.name).toBe(hashingAlgorithm);
      });
    });

    test('SHA-1 should not be supported', async () => {
      await expect(generateRSAKeyPair({ hashingAlgorithm: 'SHA-1' })).rejects.toThrow(
        'SHA-1 is disallowed by RS-018',
      );
    });
  });
});

describe('generateDHKeyPair', () => {
  const stubKey: CryptoKey = {
    algorithm: { name: 'ECDH' },
    extractable: true,
    type: 'private',
    usages: [],
  };
  const stubECDHKeyPair: CryptoKeyPair = {
    privateKey: stubKey,
    publicKey: stubKey,
  };

  const mockGenerateKey = jest.spyOn(CryptoEngine.prototype, 'generateKey');
  beforeEach(() => {
    mockGenerateKey.mockReset();
    // @ts-ignore
    mockGenerateKey.mockImplementation(() => Promise.resolve(stubECDHKeyPair));
  });

  afterAll(() => {
    mockGenerateKey.mockRestore();
  });

  test('The result should be a DH key pair', async () => {
    const keyPair = await generateECDHKeyPair();

    expect(keyPair).toBe(stubECDHKeyPair);

    expect(mockGenerateKey).toBeCalledTimes(1);
    const generateKeyCallArgs = mockGenerateKey.mock.calls[0];
    const algorithm = generateKeyCallArgs[0];
    expect(algorithm).toHaveProperty('name', 'ECDH');
  });

  test('NIST P-256 curve should be used by default', async () => {
    await generateECDHKeyPair();

    const generateKeyCallArgs = mockGenerateKey.mock.calls[0];
    const algorithm = generateKeyCallArgs[0];
    expect(algorithm).toHaveProperty('namedCurve', 'P-256');
  });

  test.each([['P-384', 'P-521']])('%s should also be supported', async curveName => {
    await generateECDHKeyPair(curveName as ECDHCurveName);

    const generateKeyCallArgs = mockGenerateKey.mock.calls[0];
    const algorithm = generateKeyCallArgs[0];
    expect(algorithm).toHaveProperty('namedCurve', curveName);
  });

  test('The key pair should be extractable', async () => {
    await generateECDHKeyPair();

    const generateKeyCallArgs = mockGenerateKey.mock.calls[0];

    const extractableFlag = generateKeyCallArgs[1];
    expect(extractableFlag).toBeTrue();
  });

  test('deriveKey and deriveBits should be the only uses of the keys', async () => {
    await generateECDHKeyPair();

    const generateKeyCallArgs = mockGenerateKey.mock.calls[0];
    const keyUses = generateKeyCallArgs[2];
    expect(keyUses).toHaveLength(2);
    expect(keyUses).toContain('deriveBits');
    expect(keyUses).toContain('deriveKey');
  });
});

describe('Key converters', () => {
  let stubKeyPair: CryptoKeyPair;
  beforeAll(async () => {
    stubKeyPair = await generateRSAKeyPair();
  });

  test('convertSigningPrivateKeyToEncrypting', async () => {
    const encryptionPrivateKey = await convertSignaturePrivateKeyToEncryption(
      stubKeyPair.privateKey,
    );

    expect(encryptionPrivateKey.algorithm).toEqual(stubKeyPair.privateKey.algorithm);
    expect(encryptionPrivateKey.extractable).toEqual(stubKeyPair.privateKey.extractable);
    expect(encryptionPrivateKey.type).toEqual(stubKeyPair.privateKey.type);
    expect(encryptionPrivateKey).toHaveProperty('usages', ['decrypt']);
    expectBuffersToEqual(
      await derSerializePrivateKey(encryptionPrivateKey),
      await derSerializePrivateKey(stubKeyPair.privateKey),
    );
  });

  test('convertSigningPublicKeyToEncrypting', async () => {
    const encryptionPublicKey = await convertSignaturePublicKeyToEncryption(stubKeyPair.publicKey);

    expect(encryptionPublicKey.algorithm).toEqual(stubKeyPair.publicKey.algorithm);
    expect(encryptionPublicKey.extractable).toEqual(stubKeyPair.publicKey.extractable);
    expect(encryptionPublicKey.type).toEqual(stubKeyPair.publicKey.type);
    expect(encryptionPublicKey).toHaveProperty('usages', ['encrypt']);
    expectBuffersToEqual(
      await derSerializePrivateKey(encryptionPublicKey),
      await derSerializePrivateKey(stubKeyPair.publicKey),
    );
  });
});

describe('Key serializers', () => {
  let stubKeyPair: CryptoKeyPair;
  beforeAll(async () => {
    stubKeyPair = await generateRSAKeyPair();
  });

  const stubExportedKeyDer = bufferToArray(Buffer.from('Hey'));
  const mockExportKey = jest.spyOn(CryptoEngine.prototype, 'exportKey');
  beforeEach(async () => {
    mockExportKey.mockReset();
    mockExportKey.mockResolvedValue(stubExportedKeyDer);
  });

  afterAll(() => {
    mockExportKey.mockRestore();
  });

  test('derSerializePublicKey should convert public key to buffer', async () => {
    const publicKeyDer = await derSerializePublicKey(stubKeyPair.publicKey);

    expect(publicKeyDer).toBeInstanceOf(Buffer);
    expectBuffersToEqual(publicKeyDer, Buffer.from(stubExportedKeyDer));

    expect(mockExportKey).toBeCalledTimes(1);
    expect(mockExportKey).toBeCalledWith('spki', stubKeyPair.publicKey);
  });

  test('derSerializePrivateKey should convert private key to buffer', async () => {
    const privateKeyDer = await derSerializePrivateKey(stubKeyPair.privateKey);

    expect(privateKeyDer).toBeInstanceOf(Buffer);
    expectBuffersToEqual(privateKeyDer, Buffer.from(stubExportedKeyDer));

    expect(mockExportKey).toBeCalledTimes(1);
    expect(mockExportKey).toBeCalledWith('pkcs8', stubKeyPair.privateKey);
  });
});

describe('Key deserializers', () => {
  const stubKeyDer = Buffer.from('Hey');
  const rsaAlgorithmOptions: RsaHashedImportParams = { name: 'RSA-PSS', hash: { name: 'SHA-256' } };
  const ecdhAlgorithmOptions: EcKeyImportParams = { name: 'ECDH', namedCurve: 'P-256' };

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

  test('derDeserializeECDHPublicKey should convert DER public key to ECDH key', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);

    const publicKey = await derDeserializeECDHPublicKey(stubKeyDer, ecdhAlgorithmOptions);

    expect(publicKey).toBe(stubKeyPair.publicKey);
    expect(mockImportKey).toBeCalledTimes(1);
    expect(mockImportKey).toBeCalledWith(
      'spki',
      bufferToArray(stubKeyDer),
      ecdhAlgorithmOptions,
      true,
      [],
    );
  });

  test('derDeserializeECDHPrivateKey should convert DER private key to ECDH key', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.privateKey);

    const privateKey = await derDeserializeECDHPrivateKey(stubKeyDer, ecdhAlgorithmOptions);

    expect(privateKey).toBe(stubKeyPair.privateKey);
    expect(mockImportKey).toBeCalledTimes(1);
    expect(mockImportKey).toBeCalledWith(
      'pkcs8',
      bufferToArray(stubKeyDer),
      ecdhAlgorithmOptions,
      true,
      ['deriveBits', 'deriveKey'],
    );
  });
});
