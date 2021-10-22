import { OctetString, Sequence, VisibleString } from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';

import { arrayBufferFrom } from '../_test_utils';
import { derSerializeHeterogeneousSequence } from '../asn1';
import { derDeserialize } from '../crypto_wrappers/_utils';
import {
  derSerializePublicKey,
  generateECDHKeyPair,
  generateRSAKeyPair,
} from '../crypto_wrappers/keys';
import { InvalidPublicNodeConnectionParams } from './InvalidPublicNodeConnectionParams';
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
  let identityKeySerialized: ArrayBuffer;
  let sessionKeySerialized: ArrayBuffer;
  beforeAll(async () => {
    identityKeySerialized = bufferToArray(await derSerializePublicKey(identityKey));
    sessionKeySerialized = bufferToArray(await derSerializePublicKey(sessionKey));
  });

  const malformedErrorMessage = 'Serialization is not a valid PublicNodeConnectionParams';

  test('Serialization should be DER sequence', async () => {
    const invalidSerialization = arrayBufferFrom('nope.jpg');

    await expect(
      PublicNodeConnectionParams.deserialize(invalidSerialization),
    ).rejects.toThrowWithMessage(InvalidPublicNodeConnectionParams, malformedErrorMessage);
  });

  test('Sequence should have at least three items', async () => {
    const invalidSerialization = derSerializeHeterogeneousSequence(
      new OctetString({ valueHex: arrayBufferFrom('nope.jpg') }),
      new OctetString({ valueHex: arrayBufferFrom('whoops.jpg') }),
    );

    await expect(
      PublicNodeConnectionParams.deserialize(invalidSerialization),
    ).rejects.toThrowWithMessage(InvalidPublicNodeConnectionParams, malformedErrorMessage);
  });

  test('Public address should be syntactically valid', async () => {
    const invalidPublicAddress = 'not a public address';
    const invalidSerialization = derSerializeHeterogeneousSequence(
      new VisibleString({ value: invalidPublicAddress }),
      new OctetString({ valueHex: identityKeySerialized }),
      new OctetString({ valueHex: sessionKeySerialized }),
    );

    await expect(PublicNodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrow(
      new InvalidPublicNodeConnectionParams(
        `Public address is syntactically invalid (${invalidPublicAddress})`,
      ),
    );
  });

  test('Identity key should be a valid RSA public key', async () => {
    const invalidSerialization = derSerializeHeterogeneousSequence(
      new VisibleString({ value: PUBLIC_ADDRESS }),
      new OctetString({
        valueHex: sessionKeySerialized, // Wrong type of key
      }),
      new OctetString({ valueHex: sessionKeySerialized }),
    );

    await expect(
      PublicNodeConnectionParams.deserialize(invalidSerialization),
    ).rejects.toThrowWithMessage(
      InvalidPublicNodeConnectionParams,
      /^Identity key is not a valid RSA public key/,
    );
  });

  test('Session key should be a valid ECDH public key', async () => {
    const invalidSerialization = derSerializeHeterogeneousSequence(
      new VisibleString({ value: PUBLIC_ADDRESS }),
      new OctetString({ valueHex: identityKeySerialized }),
      new OctetString({
        valueHex: identityKeySerialized, // Wrong type of key
      }),
    );

    await expect(
      PublicNodeConnectionParams.deserialize(invalidSerialization),
    ).rejects.toThrowWithMessage(
      InvalidPublicNodeConnectionParams,
      /^Session key is not a valid ECDH public key/,
    );
  });

  test('Valid serialization should be deserialized', async () => {
    const params = new PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);
    const serialization = await params.serialize();

    const paramsDeserialized = await PublicNodeConnectionParams.deserialize(serialization);

    expect(paramsDeserialized.publicAddress).toEqual(PUBLIC_ADDRESS);
    await expect(derSerializePublicKey(paramsDeserialized.identityKey)).resolves.toEqual(
      Buffer.from(identityKeySerialized),
    );
    await expect(derSerializePublicKey(paramsDeserialized.sessionKey)).resolves.toEqual(
      Buffer.from(sessionKeySerialized),
    );
  });
});
