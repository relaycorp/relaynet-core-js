import { OctetString, Sequence } from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import { expectBuffersToEqual } from '../../_test_utils';
import { derDeserialize } from '../../crypto_wrappers/_utils';

import RAMFError from '../../ramf/RAMFError';
import ServiceMessage from './ServiceMessage';

const TYPE = 'the type';
const CONTENT = Buffer.from('the content');

describe('ServiceMessage', () => {
  describe('serialize', () => {
    test('Type should be serialized', () => {
      const message = new ServiceMessage(TYPE, CONTENT);

      const serialization = message.serialize();

      const sequence = derDeserialize(serialization);
      expect(sequence).toBeInstanceOf(Sequence);
      expect((sequence as Sequence).valueBlock.value[0]).toHaveProperty('valueBlock.value', TYPE);
    });

    test('Content should be serialized', () => {
      const message = new ServiceMessage(TYPE, CONTENT);

      const serialization = message.serialize();

      const sequence = derDeserialize(serialization);
      expect(sequence).toBeInstanceOf(Sequence);
      expectBuffersToEqual(
        bufferToArray(CONTENT),
        ((sequence as Sequence).valueBlock.value[1] as OctetString).valueBlock.valueHex,
      );
    });
  });

  describe('deserialize', () => {
    test('Invalid buffers should result in an error', () => {
      const invalidBuffer = bufferToArray(Buffer.from('nope.jpeg'));
      expect(() => ServiceMessage.deserialize(invalidBuffer)).toThrowWithMessage(
        RAMFError,
        'Invalid service message serialization',
      );
    });

    test('A valid serialization should result in a new ServiceMessage', () => {
      const originalMessage = new ServiceMessage(TYPE, Buffer.from('Hey'));
      const serialization = bufferToArray(Buffer.from(originalMessage.serialize()));

      const finalMessage = ServiceMessage.deserialize(serialization);
      expect(finalMessage.type).toEqual(originalMessage.type);
      expect(finalMessage.content.equals(originalMessage.content)).toBeTrue();
    });

    test('Value length prefix should be decoded in little-endian', () => {
      const valueLength = 0x0100; // Two *different* octets, so endianness matters
      const originalMessage = new ServiceMessage(TYPE, Buffer.from('A'.repeat(valueLength)));
      const serialization = bufferToArray(Buffer.from(originalMessage.serialize()));

      const finalMessage = ServiceMessage.deserialize(serialization);
      expect(finalMessage.content).toHaveLength(valueLength);
    });
  });
});
