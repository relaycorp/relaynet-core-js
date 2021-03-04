import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';

import { arrayBufferFrom, expectBuffersToEqual, getAsn1SequenceItem } from '../../_test_utils';
import { derSerializeHeterogeneousSequence } from '../../asn1';
import { derDeserialize } from '../../crypto_wrappers/_utils';
import InvalidMessageError from '../InvalidMessageError';
import ServiceMessage from './ServiceMessage';

const TYPE = 'the type';
const CONTENT = Buffer.from('the content');

describe('ServiceMessage', () => {
  describe('serialize', () => {
    test('Type should be serialized', () => {
      const message = new ServiceMessage(TYPE, CONTENT);

      const serialization = message.serialize();

      const sequence = derDeserialize(serialization);
      expect(sequence).toBeInstanceOf(asn1js.Sequence);
      const typeASN1 = getAsn1SequenceItem(sequence, 0);
      expect(typeASN1.valueBlock.valueHex).toEqual(arrayBufferFrom(TYPE));
    });

    test('Content should be serialized', () => {
      const message = new ServiceMessage(TYPE, CONTENT);

      const serialization = message.serialize();

      const sequence = derDeserialize(serialization);
      expect(sequence).toBeInstanceOf(asn1js.Sequence);
      const contentASN1 = getAsn1SequenceItem(sequence, 1);
      expectBuffersToEqual(bufferToArray(CONTENT), contentASN1.valueBlock.valueHex);
    });
  });

  describe('deserialize', () => {
    test('Serialization should be DER sequence', () => {
      const invalidSerialization = new asn1js.Null().toBER(false);
      expect(() => ServiceMessage.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Invalid service message serialization',
      );
    });

    test('Sequence should have at least two items', () => {
      const invalidSerialization = derSerializeHeterogeneousSequence(
        new asn1js.VisibleString({ value: 'foo' }),
      );
      expect(() => ServiceMessage.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Invalid service message serialization',
      );
    });

    test('Valid service message should be accepted', () => {
      const originalMessage = new ServiceMessage(TYPE, Buffer.from('Hey'));
      const serialization = bufferToArray(Buffer.from(originalMessage.serialize()));

      const finalMessage = ServiceMessage.deserialize(serialization);
      expect(finalMessage.type).toEqual(originalMessage.type);
      expectBuffersToEqual(originalMessage.content, finalMessage.content);
    });
  });
});
