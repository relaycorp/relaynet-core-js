import { ECDHCurveName, HashingAlgorithm, RSAModulus } from '../algorithms';
import { generateECDHKeyPair, generateRSAKeyPair, getRSAPublicKeyFromPrivate } from './generation';
import { derSerializePublicKey } from './serialisation';

describe('generateRsaKeyPair', () => {
  test('Keys should be RSA-PSS', async () => {
    const keyPair = await generateRSAKeyPair();

    expect(keyPair.publicKey.algorithm.name).toEqual('RSA-PSS');
    expect(keyPair.privateKey.algorithm.name).toEqual('RSA-PSS');
  });

  test('Keys should be extractable', async () => {
    const keyPair = await generateRSAKeyPair();

    expect(keyPair.publicKey.extractable).toEqual(true);
    expect(keyPair.privateKey.extractable).toEqual(true);
  });

  test('Key usages should be used for signatures only', async () => {
    const keyPair = await generateRSAKeyPair();

    expect(keyPair).toHaveProperty('publicKey.usages', ['verify']);
    expect(keyPair).toHaveProperty('privateKey.usages', ['sign']);
  });

  describe('Modulus', () => {
    test('Default modulus should be 2048', async () => {
      const keyPair = await generateRSAKeyPair();
      expect(keyPair.publicKey.algorithm).toHaveProperty('modulusLength', 2048);
      expect(keyPair.privateKey.algorithm).toHaveProperty('modulusLength', 2048);
    });

    test.each([2048, 3072, 4096] as readonly RSAModulus[])(
      'Modulus %s should be used if explicitly requested',
      async () => {
        const modulus = 4096;
        const keyPair = await generateRSAKeyPair({ modulus });
        expect(keyPair.publicKey.algorithm).toHaveProperty('modulusLength', modulus);
        expect(keyPair.privateKey.algorithm).toHaveProperty('modulusLength', modulus);
      },
    );

    test('Modulus < 2048 should not supported', async () => {
      await expect(generateRSAKeyPair({ modulus: 1024 } as any)).rejects.toThrow(
        'RSA modulus must be => 2048 per RS-018 (got 1024)',
      );
    });
  });

  describe('Hashing algorithm', () => {
    test('SHA-256 should be used by default', async () => {
      const keyPair = await generateRSAKeyPair();
      expect(keyPair.publicKey.algorithm).toHaveProperty('hash.name', 'SHA-256');
      expect(keyPair.privateKey.algorithm).toHaveProperty('hash.name', 'SHA-256');
    });

    test.each(['SHA-384', 'SHA-512'] as readonly HashingAlgorithm[])(
      '%s hashing should be supported',
      async (hashingAlgorithm) => {
        const keyPair = await generateRSAKeyPair({ hashingAlgorithm });
        expect(keyPair.publicKey.algorithm).toHaveProperty('hash.name', hashingAlgorithm);
        expect(keyPair.privateKey.algorithm).toHaveProperty('hash.name', hashingAlgorithm);
      },
    );

    test('SHA-1 should not be supported', async () => {
      await expect(generateRSAKeyPair({ hashingAlgorithm: 'SHA-1' } as any)).rejects.toThrow(
        'SHA-1 is disallowed by RS-018',
      );
    });
  });
});

describe('generateDHKeyPair', () => {
  test('The result should be a DH key pair', async () => {
    const keyPair = await generateECDHKeyPair();

    expect(keyPair).toHaveProperty('privateKey.algorithm.name', 'ECDH');
    expect(keyPair).toHaveProperty('publicKey.algorithm.name', 'ECDH');
  });

  test('NIST P-256 curve should be used by default', async () => {
    const keyPair = await generateECDHKeyPair();

    expect(keyPair).toHaveProperty('privateKey.algorithm.namedCurve', 'P-256');
    expect(keyPair).toHaveProperty('publicKey.algorithm.namedCurve', 'P-256');
  });

  test.each([['P-384', 'P-521']])('%s should also be supported', async (curveName) => {
    const keyPair = await generateECDHKeyPair(curveName as ECDHCurveName);

    expect(keyPair).toHaveProperty('privateKey.algorithm.namedCurve', curveName);
    expect(keyPair).toHaveProperty('publicKey.algorithm.namedCurve', curveName);
  });

  test('The key pair should be extractable', async () => {
    const keyPair = await generateECDHKeyPair();

    expect(keyPair).toHaveProperty('privateKey.extractable', true);
    expect(keyPair).toHaveProperty('publicKey.extractable', true);
  });

  test('deriveKey and deriveBits should be the only uses of the private keys', async () => {
    const keyPair = await generateECDHKeyPair();

    expect(keyPair.privateKey.usages).toContainValues(['deriveBits', 'deriveKey']);
    expect(keyPair.publicKey.usages).toBeEmpty();
  });
});

describe('getRSAPublicKeyFromPrivate', () => {
  test('Public key should be returned', async () => {
    const keyPair = await generateRSAKeyPair();

    const publicKey = await getRSAPublicKeyFromPrivate(keyPair.privateKey);

    // It's important to check we got a public key before checking its serialisation. If we try to
    // serialise a private key with SPKI, it'd internally use the public key first.
    expect(publicKey.type).toEqual(keyPair.publicKey.type);
    await expect(derSerializePublicKey(publicKey)).resolves.toEqual(
      await derSerializePublicKey(keyPair.publicKey),
    );
  });

  test('Public key should honour algorithm parameters', async () => {
    const keyPair = await generateRSAKeyPair();

    const publicKey = await getRSAPublicKeyFromPrivate(keyPair.privateKey);

    expect(publicKey.algorithm).toEqual(keyPair.publicKey.algorithm);
  });

  test('Public key should only be used to verify signatures', async () => {
    const keyPair = await generateRSAKeyPair();

    const publicKey = await getRSAPublicKeyFromPrivate(keyPair.privateKey);

    expect(publicKey.usages).toEqual(['verify']);
  });
});
