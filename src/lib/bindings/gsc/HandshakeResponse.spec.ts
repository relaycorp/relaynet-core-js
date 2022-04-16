import { Constructed, Integer, OctetString, Sequence } from 'asn1js';

import { arrayBufferFrom, expectArrayBuffersToEqual } from '../../_test_utils';
import { makeImplicitlyTaggedSequence } from '../../asn1';
import { derDeserialize } from '../../crypto_wrappers/_utils';
import InvalidMessageError from '../../messages/InvalidMessageError';
import { HandshakeResponse } from './HandshakeResponse';

const SIGNATURE1 = arrayBufferFrom('Signature 1');
const SIGNATURE2 = arrayBufferFrom('Signature 2');

describe('serialize', () => {
  test('Output should be an ASN.1 SEQUENCE', () => {
    const response = new HandshakeResponse([]);

    const serialization = response.serialize();

    const sequence = derDeserialize(serialization);
    expect(sequence).toBeInstanceOf(Sequence);
  });

  test('No signatures', () => {
    const response = new HandshakeResponse([]);

    const serialization = response.serialize();

    const sequence = derDeserialize(serialization) as Sequence;
    expect(sequence.valueBlock.value).toHaveLength(1);
  });

  test('One signature', () => {
    const response = new HandshakeResponse([SIGNATURE1]);

    const serialization = response.serialize();

    const sequence = derDeserialize(serialization) as Sequence;
    expect(sequence.valueBlock.value).toHaveLength(1);
    expect(sequence.valueBlock.value[0]).toBeInstanceOf(Constructed);

    const nonceSignaturesASN1 = sequence.valueBlock.value[0] as Constructed;
    expect(nonceSignaturesASN1.valueBlock.value).toHaveLength(1);
    expect(nonceSignaturesASN1.valueBlock.value[0]).toBeInstanceOf(OctetString);
    expectArrayBuffersToEqual(
      SIGNATURE1,
      (nonceSignaturesASN1.valueBlock.value[0] as OctetString).valueBlock.valueHex,
    );
  });

  test('Two signatures', () => {
    const response = new HandshakeResponse([SIGNATURE1, SIGNATURE2]);

    const serialization = response.serialize();

    const sequence = derDeserialize(serialization) as Sequence;
    expect(sequence.valueBlock.value).toHaveLength(1);
    expect(sequence.valueBlock.value[0]).toBeInstanceOf(Constructed);

    const nonceSignaturesASN1 = sequence.valueBlock.value[0] as Constructed;
    expect(nonceSignaturesASN1.valueBlock.value).toHaveLength(2);
    expect(nonceSignaturesASN1.valueBlock.value[0]).toBeInstanceOf(OctetString);
    expectArrayBuffersToEqual(
      SIGNATURE1,
      (nonceSignaturesASN1.valueBlock.value[0] as OctetString).valueBlock.valueHex,
    );
    expect(nonceSignaturesASN1.valueBlock.value[1]).toBeInstanceOf(OctetString);
    expectArrayBuffersToEqual(
      SIGNATURE2,
      (nonceSignaturesASN1.valueBlock.value[1] as OctetString).valueBlock.valueHex,
    );
  });
});

describe('deserialize', () => {
  test('Invalid serialization should be refused', () => {
    const invalidSerialization = makeImplicitlyTaggedSequence(new Integer({ value: 42 })).toBER();

    expect(() => HandshakeResponse.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      'Handshake response is malformed',
    );
  });

  test('Valid serialization should be accepted', () => {
    const response = new HandshakeResponse([SIGNATURE1, SIGNATURE2]);
    const serialization = response.serialize();

    const responseDeserialized = HandshakeResponse.deserialize(serialization);

    expect(responseDeserialized.nonceSignatures).toHaveLength(2);
    expectArrayBuffersToEqual(responseDeserialized.nonceSignatures[0], SIGNATURE1);
    expectArrayBuffersToEqual(responseDeserialized.nonceSignatures[1], SIGNATURE2);
  });
});
