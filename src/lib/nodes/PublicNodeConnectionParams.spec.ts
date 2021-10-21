import { Sequence } from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';

import { arrayBufferFrom } from '../_test_utils';
import { derDeserialize } from '../crypto_wrappers/_utils';
import {
  derSerializePublicKey,
  generateECDHKeyPair,
  generateRSAKeyPair,
} from '../crypto_wrappers/keys';
import { PublicNodeConnectionParams } from './PublicNodeConnectionParams';

const PUBLIC_ADDRESS = 'example.com';

let identityKey: CryptoKey;
let sessionKey: CryptoKey;
beforeAll(async () => {
  const identityKeyPair = await generateRSAKeyPair();
  identityKey = identityKeyPair.publicKey;

  const sessionKeyPair = await generateECDHKeyPair();
  sessionKey = sessionKeyPair.publicKey;
});

describe('serialize', () => {
  test('Public address should be serialized', async () => {
    const params = new PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);

    const serialization = await params.serialize();

    const sequence = derDeserialize(serialization);
    expect(sequence).toBeInstanceOf(Sequence);
    expect((sequence as Sequence).valueBlock.value[0]).toHaveProperty(
      'valueBlock.valueHex',
      arrayBufferFrom(PUBLIC_ADDRESS),
    );
  });

  test('Identity key should be serialized', async () => {
    const params = new PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);

    const serialization = await params.serialize();

    const sequence = derDeserialize(serialization);
    expect(sequence).toBeInstanceOf(Sequence);
    expect((sequence as Sequence).valueBlock.value[1]).toHaveProperty(
      'valueBlock.valueHex',
      bufferToArray(await derSerializePublicKey(identityKey)),
    );
  });

  test('Session key should be serialized', async () => {
    const params = new PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);

    const serialization = await params.serialize();

    const sequence = derDeserialize(serialization);
    expect(sequence).toBeInstanceOf(Sequence);
    expect((sequence as Sequence).valueBlock.value[2]).toHaveProperty(
      'valueBlock.valueHex',
      bufferToArray(await derSerializePublicKey(sessionKey)),
    );
  });
});

describe('deserialized', () => {
  test.todo('Serialization should be DER sequence');

  test.todo('Sequence should have at least three items');

  test.todo('Public address should be syntactically valid');

  test.todo('Identity key should be a valid RSA public key');

  test.todo('Session key should be a valid ECDH public key');

  test.todo('Valid serialization should be accepted');
});
