import { Parser } from 'binary-parser';
import bufferToArray from 'buffer-to-arraybuffer';

import RAMFError from '../../ramf/RAMFError';
import InvalidMessageError from '../InvalidMessageError';
import ServiceMessage from './ServiceMessage';

const TYPE = 'text/plain';

describe('ServiceMessage', () => {
  describe('serialize', () => {
    const serviceMessageParser = new Parser()
      .endianess('little')
      .uint8('messageTypeLength')
      .string('messageType', { length: 'messageTypeLength', encoding: 'utf8' })
      .uint32('messageLength')
      .buffer('message', { length: 'messageLength' });

    test('A type with a length longer than 8 bits should be refused', () => {
      const maxLength = 2 ** 8 - 1; // 8 bits
      const message = new ServiceMessage('a'.repeat(maxLength + 1), Buffer.allocUnsafe(0));

      expect(() => message.serialize()).toThrowWithMessage(
        RAMFError,
        'Service message type exceeds maximum length',
      );
    });

    test('A value with a length longer than 23 bits should be refused', () => {
      const maxLength = 2 ** 23 - 1;
      const message = new ServiceMessage('a', Buffer.allocUnsafe(maxLength + 1));

      expect(() => message.serialize()).toThrowWithMessage(
        RAMFError,
        'Service message value exceeds maximum length',
      );
    });

    test('Result should match structure defined in Relaynet Core', () => {
      const value = Buffer.from('Hi');
      const message = new ServiceMessage(TYPE, value);

      const serialization = Buffer.from(message.serialize());
      const messageParts = serviceMessageParser.parse(serialization);
      expect(messageParts).toHaveProperty('messageTypeLength', TYPE.length);
      expect(messageParts).toHaveProperty('messageType', TYPE);
      expect(messageParts).toHaveProperty('messageLength', value.byteLength);
      expect(value.equals(messageParts.message)).toBeTrue();
    });

    test('Type should be encoded in UTF-8', () => {
      const type = 'こんにちは';
      const message = new ServiceMessage(type, Buffer.from('Hi'));

      const serialization = Buffer.from(message.serialize());
      const messageParts = serviceMessageParser.parse(serialization);
      expect(messageParts).toHaveProperty('messageType', type);
    });

    test('Value length prefix should be encoded in little-endian', () => {
      const valueLength = 0x0100; // Two *different* octets, so endianness matters
      const message = new ServiceMessage(TYPE, Buffer.from('A'.repeat(valueLength)));

      const serialization = Buffer.from(message.serialize());
      const messageParts = serviceMessageParser.parse(serialization);
      expect(messageParts).toHaveProperty('messageLength', valueLength);
    });

    test('A type/value reaching maximum length for a service message should be accepted', () => {
      const maxValueLength = ServiceMessage.MAX_LENGTH - 1 - TYPE.length - 4;
      const value = Buffer.from('a'.repeat(maxValueLength));
      const message = new ServiceMessage(TYPE, value);

      const serialization = message.serialize();

      expect(serialization.byteLength).toEqual(ServiceMessage.MAX_LENGTH);
    });

    test('A type/value exceeding maximum length for a service message should be refused', () => {
      const maxValueLength = ServiceMessage.MAX_LENGTH - 1 - TYPE.length - 4;
      const value = Buffer.from('a'.repeat(maxValueLength + 1));
      const message = new ServiceMessage(TYPE, value);

      expect(() => message.serialize()).toThrowWithMessage(
        InvalidMessageError,
        `Service message must not exceed ${ServiceMessage.MAX_LENGTH} octets ` +
          `(got ${ServiceMessage.MAX_LENGTH + 1} octets)`,
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
      expect(finalMessage.value.equals(originalMessage.value)).toBeTrue();
    });

    test('Value length prefix should be decoded in little-endian', () => {
      const valueLength = 0x0100; // Two *different* octets, so endianness matters
      const originalMessage = new ServiceMessage(TYPE, Buffer.from('A'.repeat(valueLength)));
      const serialization = bufferToArray(Buffer.from(originalMessage.serialize()));

      const finalMessage = ServiceMessage.deserialize(serialization);
      expect(finalMessage.value).toHaveLength(valueLength);
    });
  });
});
