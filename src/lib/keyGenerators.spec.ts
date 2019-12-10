import * as crypto from 'crypto';
import { CryptoEngine } from 'pkijs';

import { expectBuffersToEqual } from './_test_utils';
import * as modp from './crypto_wrappers/modp';
import { generateDHKeyPair, generateRsaKeyPair } from './keyGenerators';

import MockInstance = jest.MockInstance;

describe('generateRsaKeyPair', () => {
  test('Keys should be RSA', async () => {
    const keyPair = await generateRsaKeyPair();

    expect(keyPair.publicKey.algorithm.name).toMatch(/^RSA-/);
    expect(keyPair.privateKey.algorithm.name).toMatch(/^RSA-/);
  });

  test('Keys should be extractable', async () => {
    const keyPair = await generateRsaKeyPair();

    expect(keyPair.publicKey.extractable).toBe(true);
    expect(keyPair.privateKey.extractable).toBe(true);
  });

  describe('Modulus', () => {
    test('Default modulus should be 2048', async () => {
      const keyPair = await generateRsaKeyPair();
      // @ts-ignore
      expect(keyPair.publicKey.algorithm.modulusLength).toBe(2048);
      // @ts-ignore
      expect(keyPair.privateKey.algorithm.modulusLength).toBe(2048);
    });

    test('Modulus > 2048 should be supported', async () => {
      const modulus = 3072;
      const keyPair = await generateRsaKeyPair({ modulus });
      // @ts-ignore
      expect(keyPair.publicKey.algorithm.modulusLength).toBe(modulus);
      // @ts-ignore
      expect(keyPair.privateKey.algorithm.modulusLength).toBe(modulus);
    });

    test('Modulus < 2048 should not supported', async () => {
      await expect(generateRsaKeyPair({ modulus: 1024 })).rejects.toThrow(
        'RSA modulus must be => 2048 per RS-018 (got 1024)',
      );
    });
  });

  describe('Hashing algorithm', () => {
    test('SHA-256 should be used by default', async () => {
      const keyPair = await generateRsaKeyPair();
      // @ts-ignore
      expect(keyPair.publicKey.algorithm.hash.name).toBe('SHA-256');
      // @ts-ignore
      expect(keyPair.privateKey.algorithm.hash.name).toBe('SHA-256');
    });

    ['SHA-384', 'SHA-512'].forEach(hashingAlgorithm => {
      test(`${hashingAlgorithm} should be supported`, async () => {
        const keyPair = await generateRsaKeyPair({ hashingAlgorithm });
        // @ts-ignore
        expect(keyPair.publicKey.algorithm.hash.name).toBe(hashingAlgorithm);
        // @ts-ignore
        expect(keyPair.privateKey.algorithm.hash.name).toBe(hashingAlgorithm);
      });
    });

    test('SHA-1 should not be supported', async () => {
      await expect(generateRsaKeyPair({ hashingAlgorithm: 'SHA-1' })).rejects.toThrow(
        'SHA-1 is disallowed by RS-018',
      );
    });
  });
});

describe('generateDHKeyPair', () => {
  const stubKey: CryptoKey = {
    algorithm: { name: 'DH' },
    extractable: true,
    type: 'private',
    usages: [],
  };
  const stubDHKeyPair: CryptoKeyPair = {
    privateKey: stubKey,
    publicKey: stubKey,
  };

  beforeEach(() => {
    jest
      .spyOn(CryptoEngine.prototype, 'generateKey')
      // @ts-ignore
      .mockImplementationOnce(() => Promise.resolve(stubDHKeyPair));

    jest.spyOn(crypto, 'getDiffieHellman');
    jest.spyOn(modp, 'getModpGroupData');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('The result should be a DH key pair', async () => {
    const dhKeyPair = await generateDHKeyPair();

    expect(dhKeyPair).toBe(stubDHKeyPair);
  });

  test('MODP Group 14 should be used by default', async () => {
    await generateDHKeyPair();

    const generateKeyCallArgs = ((CryptoEngine.prototype.generateKey as unknown) as MockInstance<
      any,
      any
    >).mock.calls[0];

    const modp14Group = modp.getModpGroupData('modp14');

    const algorithm = generateKeyCallArgs[0];
    expect(algorithm).toHaveProperty('name', 'DH');
    expectBuffersToEqual(algorithm.prime, modp14Group.prime);
    expectBuffersToEqual(algorithm.generator, modp14Group.generator);
  });

  test.each([['modp15', 'modp16', 'modp17', 'modp18']])(
    '%s should also be supported',
    async groupName => {
      await generateDHKeyPair(groupName as modp.MODPGroupName);

      expect(modp.getModpGroupData).toBeCalledWith(groupName);
    },
  );

  test('The key pair should be extractable', async () => {
    await generateDHKeyPair();

    const generateKeyCallArgs = ((CryptoEngine.prototype.generateKey as unknown) as MockInstance<
      any,
      any
    >).mock.calls[0];

    const extractableFlag = generateKeyCallArgs[1];
    expect(extractableFlag).toBeTrue();
  });

  test('deriveKey and deriveBits should be the only uses of the keys', async () => {
    await generateDHKeyPair();

    const generateKeyCallArgs = ((CryptoEngine.prototype.generateKey as unknown) as MockInstance<
      any,
      any
    >).mock.calls[0];

    const keyUses = generateKeyCallArgs[2];
    expect(keyUses).toHaveLength(2);
    expect(keyUses).toContain('deriveBits');
    expect(keyUses).toContain('deriveKey');
  });
});
