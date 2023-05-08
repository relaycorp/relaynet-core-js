import { Constructed, OctetString, Sequence, VisibleString } from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';

import { arrayBufferFrom } from '../_test_utils';
import { makeImplicitlyTaggedSequence } from '../asn1';
import { derDeserialize } from '../crypto/_utils';
import { derSerializePublicKey, generateECDHKeyPair, generateRSAKeyPair } from '../crypto/keys';
import { SessionKey } from '../SessionKey';
import { InvalidNodeConnectionParams } from './errors';
import { NodeConnectionParams } from './NodeConnectionParams';

const INTERNET_ADDRESS = 'example.com';

let identityKey: CryptoKey;
let sessionKey: SessionKey;
beforeAll(async () => {
  const identityKeyPair = await generateRSAKeyPair();
  identityKey = identityKeyPair.publicKey;

  const sessionKeyPair = await generateECDHKeyPair();
  sessionKey = {
    keyId: Buffer.from('key id'),
    publicKey: sessionKeyPair.publicKey,
  };
});

describe('serialize', () => {
  test('Internet address should be serialized', async () => {
    const params = new NodeConnectionParams(INTERNET_ADDRESS, identityKey, sessionKey);

    const serialization = await params.serialize();

    const sequence = derDeserialize(serialization);
    expect(sequence).toBeInstanceOf(Sequence);
    expect((sequence as Sequence).valueBlock.value[0]).toHaveProperty(
      'valueBlock.valueHex',
      arrayBufferFrom(INTERNET_ADDRESS),
    );
  });

  test('Identity key should be serialized', async () => {
    const params = new NodeConnectionParams(INTERNET_ADDRESS, identityKey, sessionKey);

    const serialization = await params.serialize();

    const sequence = derDeserialize(serialization);
    expect(sequence).toBeInstanceOf(Sequence);
    expect((sequence as Sequence).valueBlock.value[1]).toHaveProperty(
      'valueBlock.valueHex',
      bufferToArray(await derSerializePublicKey(identityKey)),
    );
  });

  describe('Session key', () => {
    test('Session key should be a CONSTRUCTED value', async () => {
      const params = new NodeConnectionParams(INTERNET_ADDRESS, identityKey, sessionKey);

      const serialization = await params.serialize();

      const sequence = derDeserialize(serialization);
      const sessionKeySequence = (sequence as Sequence).valueBlock.value[2];
      expect(sessionKeySequence).toBeInstanceOf(Constructed);
    });

    test('Id should be serialized', async () => {
      const params = new NodeConnectionParams(INTERNET_ADDRESS, identityKey, sessionKey);

      const serialization = await params.serialize();

      const sequence = derDeserialize(serialization);
      expect(
        ((sequence as Sequence).valueBlock.value[2] as Sequence).valueBlock.value[0],
      ).toHaveProperty('valueBlock.valueHex', bufferToArray(sessionKey.keyId));
    });

    test('Public key should be serialized', async () => {
      const params = new NodeConnectionParams(INTERNET_ADDRESS, identityKey, sessionKey);

      const serialization = await params.serialize();

      const sequence = derDeserialize(serialization);
      expect(
        ((sequence as Sequence).valueBlock.value[2] as Sequence).valueBlock.value[1],
      ).toHaveProperty(
        'valueBlock.valueHex',
        bufferToArray(await derSerializePublicKey(sessionKey.publicKey)),
      );
    });
  });
});

describe('deserialize', () => {
  let identityKeySerialized: ArrayBuffer;
  let sessionKeySerialized: ArrayBuffer;
  beforeAll(async () => {
    identityKeySerialized = bufferToArray(await derSerializePublicKey(identityKey));
    sessionKeySerialized = bufferToArray(await derSerializePublicKey(sessionKey.publicKey));
  });

  let sessionKeySequence: Sequence;
  beforeAll(() => {
    sessionKeySequence = makeImplicitlyTaggedSequence(
      new OctetString({ valueHex: bufferToArray(sessionKey.keyId) }),
      new OctetString({ valueHex: sessionKeySerialized }),
    );
  });

  const malformedErrorMessage = 'Serialization is not a valid NodeConnectionParams';

  test('Serialization should be DER sequence', async () => {
    const invalidSerialization = arrayBufferFrom('nope.jpg');

    await expect(NodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrowWithMessage(
      InvalidNodeConnectionParams,
      malformedErrorMessage,
    );
  });

  test('Sequence should have at least three items', async () => {
    const invalidSerialization = makeImplicitlyTaggedSequence(
      new OctetString({ valueHex: arrayBufferFrom('nope.jpg') }),
      new OctetString({ valueHex: arrayBufferFrom('whoops.jpg') }),
    ).toBER();

    await expect(NodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrowWithMessage(
      InvalidNodeConnectionParams,
      malformedErrorMessage,
    );
  });

  test('Internet address should be syntactically valid', async () => {
    const invalidInternetAddress = 'not a domain name';
    const invalidSerialization = makeImplicitlyTaggedSequence(
      new VisibleString({ value: invalidInternetAddress }),
      new OctetString({ valueHex: identityKeySerialized }),
      sessionKeySequence,
    ).toBER();

    await expect(NodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrow(
      new InvalidNodeConnectionParams(
        `Internet address is syntactically invalid (${invalidInternetAddress})`,
      ),
    );
  });

  test('Identity key should be a valid RSA public key', async () => {
    const invalidSerialization = makeImplicitlyTaggedSequence(
      new VisibleString({ value: INTERNET_ADDRESS }),
      new OctetString({
        valueHex: sessionKeySerialized, // Wrong type of key
      }),
      sessionKeySequence,
    ).toBER();

    await expect(NodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrowWithMessage(
      InvalidNodeConnectionParams,
      /^Identity key is not a valid RSA public key/,
    );
  });

  describe('Session key', () => {
    test('SEQUENCE should contain at least two items', async () => {
      const invalidSerialization = makeImplicitlyTaggedSequence(
        new VisibleString({ value: INTERNET_ADDRESS }),
        new OctetString({ valueHex: identityKeySerialized }),
        makeImplicitlyTaggedSequence(
          new OctetString({ valueHex: bufferToArray(sessionKey.keyId) }),
        ),
      ).toBER();

      await expect(
        NodeConnectionParams.deserialize(invalidSerialization),
      ).rejects.toThrowWithMessage(
        InvalidNodeConnectionParams,
        'Session key should have at least two items',
      );
    });

    test('Session key should be a valid ECDH public key', async () => {
      const invalidSerialization = makeImplicitlyTaggedSequence(
        new VisibleString({ value: INTERNET_ADDRESS }),
        new OctetString({ valueHex: identityKeySerialized }),
        makeImplicitlyTaggedSequence(
          new OctetString({ valueHex: bufferToArray(sessionKey.keyId) }),
          new OctetString({
            valueHex: identityKeySerialized, // Wrong type of key
          }),
        ),
      ).toBER();

      await expect(
        NodeConnectionParams.deserialize(invalidSerialization),
      ).rejects.toThrowWithMessage(
        InvalidNodeConnectionParams,
        /^Session key is not a valid ECDH public key/,
      );
    });
  });

  test('Valid serialization should be deserialized', async () => {
    const params = new NodeConnectionParams(INTERNET_ADDRESS, identityKey, sessionKey);
    const serialization = await params.serialize();

    const paramsDeserialized = await NodeConnectionParams.deserialize(serialization);

    expect(paramsDeserialized.internetAddress).toEqual(INTERNET_ADDRESS);
    await expect(derSerializePublicKey(paramsDeserialized.identityKey)).resolves.toEqual(
      Buffer.from(identityKeySerialized),
    );
    await expect(paramsDeserialized.sessionKey.keyId).toEqual(sessionKey.keyId);
    await expect(derSerializePublicKey(paramsDeserialized.sessionKey.publicKey)).resolves.toEqual(
      Buffer.from(sessionKeySerialized),
    );
  });
});
