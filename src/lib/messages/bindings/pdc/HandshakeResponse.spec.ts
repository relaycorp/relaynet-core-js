import { OctetString, Sequence } from 'asn1js';
import { arrayBufferFrom, expectBuffersToEqual } from '../../../_test_utils';
import { derDeserialize } from '../../../crypto_wrappers/_utils';
import { HandshakeResponse } from './HandshakeResponse';

const SIGNATURE1 = arrayBufferFrom('Signature 1');
const SIGNATURE2 = arrayBufferFrom('Signature 2');

describe('serialized', () => {
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
    expect(sequence.valueBlock.value).toHaveLength(0);
  });

  test('One signature', () => {
    const response = new HandshakeResponse([SIGNATURE1]);

    const serialization = response.serialize();

    const sequence = derDeserialize(serialization) as Sequence;
    expect(sequence.valueBlock.value).toHaveLength(1);
    expect(sequence.valueBlock.value[0]).toBeInstanceOf(OctetString);
    expectBuffersToEqual(
      SIGNATURE1,
      (sequence.valueBlock.value[0] as OctetString).valueBlock.valueHex,
    );
  });

  test('Two signatures', () => {
    const response = new HandshakeResponse([SIGNATURE1, SIGNATURE2]);

    const serialization = response.serialize();

    const sequence = derDeserialize(serialization) as Sequence;
    expect(sequence.valueBlock.value).toHaveLength(2);
    expectBuffersToEqual(
      SIGNATURE1,
      (sequence.valueBlock.value[0] as OctetString).valueBlock.valueHex,
    );
    expectBuffersToEqual(
      SIGNATURE2,
      (sequence.valueBlock.value[1] as OctetString).valueBlock.valueHex,
    );
  });
});
