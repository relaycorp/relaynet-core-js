import { createHash } from 'crypto';

import { generateECDHKeyPair, generateRSAKeyPair } from './generation';
import { derSerializePublicKey } from './serialisation';
import { sha256Hex } from '../../_test_utils';
import { getIdFromIdentityKey, getPublicKeyDigest, getPublicKeyDigestHex } from './digest';

describe('getPublicKeyDigest', () => {
  let keyPair: CryptoKeyPair;
  beforeAll(async () => {
    keyPair = await generateRSAKeyPair();
  });

  test('SHA-256 digest should be returned in hex', async () => {
    const digest = await getPublicKeyDigest(keyPair.publicKey);

    expect(Buffer.from(digest)).toEqual(
      createHash('sha256')
        .update(await derSerializePublicKey(keyPair.publicKey))
        .digest(),
    );
  });

  test('Public key should be extracted first if input is private key', async () => {
    const digest = await getPublicKeyDigest(keyPair.privateKey);

    expect(Buffer.from(digest)).toEqual(
      createHash('sha256')
        .update(await derSerializePublicKey(keyPair.publicKey))
        .digest(),
    );
  });
});

test('getPublicKeyDigestHex should return the SHA-256 hex digest of the public key', async () => {
  const keyPair = await generateRSAKeyPair();

  const digestHex = await getPublicKeyDigestHex(keyPair.publicKey);

  expect(digestHex).toEqual(sha256Hex(await derSerializePublicKey(keyPair.publicKey)));
});

describe('getIdFromIdentityKey', () => {
  test('Id should be computed from identity key', async () => {
    const keyPair = await generateRSAKeyPair();

    const id = await getIdFromIdentityKey(keyPair.publicKey);

    expect(id).toEqual('0' + sha256Hex(await derSerializePublicKey(keyPair.publicKey)));
  });

  test('DH keys should be refused', async () => {
    const keyPair = await generateECDHKeyPair();

    await expect(getIdFromIdentityKey(keyPair.publicKey)).rejects.toThrowWithMessage(
      Error,
      'Only RSA keys are supported (got ECDH)',
    );
  });
});
