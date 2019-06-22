import { generateRsaKeys } from './crypto';

describe('generateRsaKeys', () => {
  test('Keys should be RSA', async () => {
    const keyPair = await generateRsaKeys();

    expect(keyPair.publicKey.algorithm.name).toMatch(/^RSA-/);
    expect(keyPair.privateKey.algorithm.name).toMatch(/^RSA-/);
  });

  test('Keys should be extractable', async () => {
    const keyPair = await generateRsaKeys();

    expect(keyPair.publicKey.extractable).toBe(true);
    expect(keyPair.privateKey.extractable).toBe(true);
  });

  describe('Modulus', () => {
    test('Default modulus should be 2048', async () => {
      const keyPair = await generateRsaKeys();
      // @ts-ignore
      expect(keyPair.publicKey.algorithm.modulusLength).toBe(2048);
      // @ts-ignore
      expect(keyPair.privateKey.algorithm.modulusLength).toBe(2048);
    });

    test('Modulus > 2048 should be supported', async () => {
      const modulus = 3072;
      const keyPair = await generateRsaKeys({ modulus });
      // @ts-ignore
      expect(keyPair.publicKey.algorithm.modulusLength).toBe(modulus);
      // @ts-ignore
      expect(keyPair.privateKey.algorithm.modulusLength).toBe(modulus);
    });

    test('Modulus < 2048 should not supported', async () => {
      await expect(generateRsaKeys({ modulus: 1024 })).rejects.toThrow(
        'RSA modulus must be => 2048 per RS-018 (got 1024)'
      );
    });
  });

  describe('Hashing algorithm', () => {
    test('SHA-256 should be used by default', async () => {
      const keyPair = await generateRsaKeys();
      // @ts-ignore
      expect(keyPair.publicKey.algorithm.hash.name).toBe('SHA-256');
      // @ts-ignore
      expect(keyPair.privateKey.algorithm.hash.name).toBe('SHA-256');
    });

    ['SHA-384', 'SHA-512'].forEach(hashingAlgorithm => {
      test(`${hashingAlgorithm} should be supported`, async () => {
        const keyPair = await generateRsaKeys({ hashingAlgorithm });
        // @ts-ignore
        expect(keyPair.publicKey.algorithm.hash.name).toBe(hashingAlgorithm);
        // @ts-ignore
        expect(keyPair.privateKey.algorithm.hash.name).toBe(hashingAlgorithm);
      });
    });

    test('SHA-1 should not be supported', async () => {
      await expect(
        generateRsaKeys({ hashingAlgorithm: 'SHA-1' })
      ).rejects.toThrow('SHA-1 is disallowed by RS-018');
    });
  });
});
