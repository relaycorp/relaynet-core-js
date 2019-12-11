import { CryptoEngine } from 'pkijs';

import { getMockContext } from '../_test_utils';
import { ECDHCurveName, generateECDHKeyPair, generateRSAKeyPair } from './keyGenerators';

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

  beforeEach(() => {
    jest
      .spyOn(CryptoEngine.prototype, 'generateKey')
      // @ts-ignore
      .mockImplementationOnce(() => Promise.resolve(stubECDHKeyPair));
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('The result should be a DH key pair', async () => {
    const keyPair = await generateECDHKeyPair();

    expect(keyPair).toBe(stubECDHKeyPair);

    expect(CryptoEngine.prototype.generateKey).toBeCalledTimes(1);
    const generateKeyCallArgs = getMockContext(CryptoEngine.prototype.generateKey).calls[0];
    const algorithm = generateKeyCallArgs[0];
    expect(algorithm).toHaveProperty('name', 'ECDH');
  });

  test('NIST P-256 curve should be used by default', async () => {
    await generateECDHKeyPair();

    const generateKeyCallArgs = getMockContext(CryptoEngine.prototype.generateKey).calls[0];
    const algorithm = generateKeyCallArgs[0];
    expect(algorithm).toHaveProperty('namedCurve', 'P-256');
  });

  test.each([['P-384', 'P-521']])('%s should also be supported', async curveName => {
    await generateECDHKeyPair(curveName as ECDHCurveName);

    const generateKeyCallArgs = getMockContext(CryptoEngine.prototype.generateKey).calls[0];
    const algorithm = generateKeyCallArgs[0];
    expect(algorithm).toHaveProperty('namedCurve', curveName);
  });

  test('The key pair should be extractable', async () => {
    await generateECDHKeyPair();

    const generateKeyCallArgs = getMockContext(CryptoEngine.prototype.generateKey).calls[0];

    const extractableFlag = generateKeyCallArgs[1];
    expect(extractableFlag).toBeTrue();
  });

  test('deriveKey and deriveBits should be the only uses of the keys', async () => {
    await generateECDHKeyPair();

    const generateKeyCallArgs = getMockContext(CryptoEngine.prototype.generateKey).calls[0];

    const keyUses = generateKeyCallArgs[2];
    expect(keyUses).toHaveLength(2);
    expect(keyUses).toContain('deriveBits');
    expect(keyUses).toContain('deriveKey');
  });
});
