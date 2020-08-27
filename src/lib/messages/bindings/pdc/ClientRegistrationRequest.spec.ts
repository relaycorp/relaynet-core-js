/* tslint:disable:no-let */

import { OctetString, VisibleString } from 'asn1js';
import { ClientRegistrationRequest, derSerializePublicKey, generateRSAKeyPair } from '../../../..';
import { arrayBufferFrom, getAsn1SequenceItem } from '../../../_test_utils';
import { serializeSequence } from '../../../asn1';
import { derDeserialize } from '../../../crypto_wrappers/_utils';
import { verify } from '../../../crypto_wrappers/rsaSigning';
import InvalidMessageError from '../../InvalidMessageError';

const craSerialized = arrayBufferFrom('The CRA');
let clientKeyPair: CryptoKeyPair;
beforeAll(async () => {
  clientKeyPair = await generateRSAKeyPair();
});

describe('serialize', () => {
  test('Client public key should be honored', async () => {
    const crr = new ClientRegistrationRequest(clientKeyPair.publicKey, craSerialized);

    const serialization = await crr.serialize(clientKeyPair.privateKey);

    const sequence = derDeserialize(serialization);
    expect(getAsn1SequenceItem(sequence, 0)).toHaveProperty(
      'valueBlock.valueHex',
      arrayBufferFrom(await derSerializePublicKey(clientKeyPair.publicKey)),
    );
  });

  test('CRA countersignature should contain correct CRA', async () => {
    const crr = new ClientRegistrationRequest(clientKeyPair.publicKey, craSerialized);

    const serialization = await crr.serialize(clientKeyPair.privateKey);

    const sequence = derDeserialize(serialization);
    expect(getAsn1SequenceItem(sequence, 1)).toHaveProperty('valueBlock.valueHex', craSerialized);
  });

  test('CRA countersignature should be valid', async () => {
    const crr = new ClientRegistrationRequest(clientKeyPair.publicKey, craSerialized);

    const serialization = await crr.serialize(clientKeyPair.privateKey);

    const sequence = derDeserialize(serialization);
    const signature = getAsn1SequenceItem(sequence, 2).valueBlock.valueHex;
    await expect(verify(signature, clientKeyPair.publicKey, craSerialized)).resolves.toBeTrue();
  });
});

describe('deserialize', () => {
  test('Malformed sequence should be refused', async () => {
    const invalidSerialization = arrayBufferFrom('nope.jpg');

    await expect(ClientRegistrationRequest.deserialize(invalidSerialization)).rejects.toEqual(
      new InvalidMessageError('Serialization is not a valid ClientRegistrationRequest'),
    );
  });

  test('Sequence should have at least 3 items', async () => {
    const invalidSerialization = serializeSequence(
      new VisibleString({ value: 'foo' }),
      new VisibleString({ value: 'bar' }),
    );

    await expect(ClientRegistrationRequest.deserialize(invalidSerialization)).rejects.toEqual(
      new InvalidMessageError('Serialization is not a valid ClientRegistrationRequest'),
    );
  });

  test('Malformed client public key should be refused', async () => {
    const invalidSerialization = serializeSequence(
      new VisibleString({ value: 'not a valid public key' }),
      new VisibleString({ value: 'foo' }),
      new VisibleString({ value: 'bar' }),
    );

    await expect(ClientRegistrationRequest.deserialize(invalidSerialization)).rejects.toEqual(
      new InvalidMessageError('Client public key is not valid'),
    );
  });

  test('Invalid CRA countersignatures should be refused', async () => {
    const invalidSerialization = serializeSequence(
      new OctetString({ valueHex: await derSerializePublicKey(clientKeyPair.publicKey) }),
      new VisibleString({ value: 'server data' }),
      new VisibleString({ value: 'invalid signature' }),
    );

    await expect(ClientRegistrationRequest.deserialize(invalidSerialization)).rejects.toEqual(
      new InvalidMessageError('CRA countersignature is invalid'),
    );
  });

  test('Valid values should be accepted', async () => {
    const crr = new ClientRegistrationRequest(clientKeyPair.publicKey, craSerialized);

    const serialization = await crr.serialize(clientKeyPair.privateKey);

    const crrDeserialized = await ClientRegistrationRequest.deserialize(serialization);
    expect(derSerializePublicKey(crrDeserialized.clientPublicKey)).toEqual(
      derSerializePublicKey(clientKeyPair.publicKey),
    );
    expect(crrDeserialized.craSerialized).toEqual(craSerialized);
  });
});
