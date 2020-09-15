/* tslint:disable:no-let */

import { ObjectIdentifier, OctetString, VisibleString } from 'asn1js';
import {
  derSerializePublicKey,
  generateRSAKeyPair,
  PrivateNodeRegistrationRequest,
} from '../../../..';
import { arrayBufferFrom, getAsn1SequenceItem } from '../../../_test_utils';
import { serializeSequence } from '../../../asn1';
import { derDeserialize } from '../../../crypto_wrappers/_utils';
import { verify } from '../../../crypto_wrappers/rsaSigning';
import { RELAYNET_OIDS } from '../../../oids';
import InvalidMessageError from '../../InvalidMessageError';

const authorizationSerialized = arrayBufferFrom('The PNRA');
let privateNodeKeyPair: CryptoKeyPair;
beforeAll(async () => {
  privateNodeKeyPair = await generateRSAKeyPair();
});

describe('serialize', () => {
  test('Private node public key should be honored', async () => {
    const request = new PrivateNodeRegistrationRequest(
      privateNodeKeyPair.publicKey,
      authorizationSerialized,
    );

    const serialization = await request.serialize(privateNodeKeyPair.privateKey);

    const sequence = derDeserialize(serialization);
    expect(getAsn1SequenceItem(sequence, 0)).toHaveProperty(
      'valueBlock.valueHex',
      arrayBufferFrom(await derSerializePublicKey(privateNodeKeyPair.publicKey)),
    );
  });

  test('Authorization should be honored', async () => {
    const request = new PrivateNodeRegistrationRequest(
      privateNodeKeyPair.publicKey,
      authorizationSerialized,
    );

    const serialization = await request.serialize(privateNodeKeyPair.privateKey);

    const sequence = derDeserialize(serialization);
    expect(getAsn1SequenceItem(sequence, 1)).toHaveProperty(
      'valueBlock.valueHex',
      authorizationSerialized,
    );
  });

  test('Authorization countersignature should be valid', async () => {
    const request = new PrivateNodeRegistrationRequest(
      privateNodeKeyPair.publicKey,
      authorizationSerialized,
    );

    const serialization = await request.serialize(privateNodeKeyPair.privateKey);

    const sequence = derDeserialize(serialization);
    const signature = getAsn1SequenceItem(sequence, 2).valueBlock.valueHex;
    const expectedPNRACountersignature = serializeSequence(
      new ObjectIdentifier({
        value: RELAYNET_OIDS.NODE_REGISTRATION.AUTHORIZATION_COUNTERSIGNATURE,
      }),
      new OctetString({ valueHex: authorizationSerialized }),
    );
    await expect(
      verify(signature, privateNodeKeyPair.publicKey, expectedPNRACountersignature),
    ).resolves.toBeTrue();
  });
});

describe('deserialize', () => {
  test('Malformed sequence should be refused', async () => {
    const invalidSerialization = arrayBufferFrom('nope.jpg');

    await expect(PrivateNodeRegistrationRequest.deserialize(invalidSerialization)).rejects.toEqual(
      new InvalidMessageError('Serialization is not a valid PrivateNodeRegistrationRequest'),
    );
  });

  test('Sequence should have at least 3 items', async () => {
    const invalidSerialization = serializeSequence(
      new VisibleString({ value: 'foo' }),
      new VisibleString({ value: 'bar' }),
    );

    await expect(PrivateNodeRegistrationRequest.deserialize(invalidSerialization)).rejects.toEqual(
      new InvalidMessageError('Serialization is not a valid PrivateNodeRegistrationRequest'),
    );
  });

  test('Malformed private node public key should be refused', async () => {
    const invalidSerialization = serializeSequence(
      new VisibleString({ value: 'not a valid public key' }),
      new VisibleString({ value: 'foo' }),
      new VisibleString({ value: 'bar' }),
    );

    await expect(PrivateNodeRegistrationRequest.deserialize(invalidSerialization)).rejects.toEqual(
      new InvalidMessageError('Private node public key is not valid'),
    );
  });

  test('Invalid countersignatures should be refused', async () => {
    const invalidSerialization = serializeSequence(
      new OctetString({ valueHex: await derSerializePublicKey(privateNodeKeyPair.publicKey) }),
      new VisibleString({ value: 'gateway data' }),
      new VisibleString({ value: 'invalid signature' }),
    );

    await expect(PrivateNodeRegistrationRequest.deserialize(invalidSerialization)).rejects.toEqual(
      new InvalidMessageError('Authorization countersignature is invalid'),
    );
  });

  test('Valid values should be accepted', async () => {
    const request = new PrivateNodeRegistrationRequest(
      privateNodeKeyPair.publicKey,
      authorizationSerialized,
    );

    const serialization = await request.serialize(privateNodeKeyPair.privateKey);

    const requestDeserialized = await PrivateNodeRegistrationRequest.deserialize(serialization);
    expect(derSerializePublicKey(requestDeserialized.privateNodePublicKey)).toEqual(
      derSerializePublicKey(privateNodeKeyPair.publicKey),
    );
    expect(requestDeserialized.pnraSerialized).toEqual(authorizationSerialized);
  });
});
