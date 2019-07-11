import { Parser } from 'binary-parser';
import RAMFError from './RAMFError';
import ServiceMessage from './ServiceMessage';

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
      const message = new ServiceMessage(
        'a'.repeat(maxLength + 1),
        Buffer.alloc(0)
      );

      expect(() => message.serialize()).toThrowWithMessage(
        RAMFError,
        'Service message type exceeds maximum length'
      );
    });

    test('A value with a length longer than 32 bits should be refused', () => {
      const maxLength = 2 ** 32; // 32 bits
      const value = Buffer.alloc(0);
      jest.spyOn(value, 'length', 'get').mockReturnValueOnce(maxLength + 1);
      const message = new ServiceMessage('text/plain', value);

      expect(() => message.serialize()).toThrowWithMessage(
        RAMFError,
        'Service message value exceeds maximum length'
      );
    });

    test('Result should match structure defined in Relaynet Core', () => {
      const type = 'text/plain';
      const value = Buffer.from('Hi');
      const message = new ServiceMessage(type, value);

      const messageParts = serviceMessageParser.parse(message.serialize());
      expect(messageParts).toHaveProperty('messageTypeLength', type.length);
      expect(messageParts).toHaveProperty('messageType', type);
      expect(messageParts).toHaveProperty('messageLength', value.byteLength);
      expect(value.equals(messageParts.message)).toBeTrue();
    });

    test('Type should be encoded in UTF-8', () => {
      const type = 'こんにちは';
      const message = new ServiceMessage(type, Buffer.from('Hi'));

      const messageParts = serviceMessageParser.parse(message.serialize());
      expect(messageParts).toHaveProperty('messageType', type);
    });

    test('Value length prefix should be encoded in little-endian', () => {
      const valueLength = 0x0100; // Two *different* octets, so endianness matters
      const message = new ServiceMessage(
        'text/plain',
        Buffer.from('A'.repeat(valueLength))
      );

      const messageParts = serviceMessageParser.parse(message.serialize());
      expect(messageParts).toHaveProperty('messageLength', valueLength);
    });
  });

  describe('deserialize', () => {
    test('Invalid buffers should result in an error', () => {
      const invalidBuffer = Buffer.from('nope.jpeg');
      expect(() =>
        ServiceMessage.deserialize(invalidBuffer)
      ).toThrowWithMessage(RAMFError, 'Invalid service message serialization');
    });

    test('A valid serialization should result in a new ServiceMessage', () => {
      const originalServiceMessage = new ServiceMessage(
        'text/plain',
        Buffer.from('Hey')
      );
      const serviceMessageSerialized = originalServiceMessage.serialize();

      const finalServiceMessage = ServiceMessage.deserialize(
        serviceMessageSerialized
      );
      expect(finalServiceMessage.type).toEqual(originalServiceMessage.type);
      expect(
        finalServiceMessage.value.equals(originalServiceMessage.value)
      ).toBeTrue();
    });

    test('Value length prefix should be decoded in little-endian', () => {
      const valueLength = 0x0100; // Two *different* octets, so endianness matters
      const originalServiceMessage = new ServiceMessage(
        'text/plain',
        Buffer.from('A'.repeat(valueLength))
      );
      const serviceMessageSerialized = originalServiceMessage.serialize();

      const finalServiceMessage = ServiceMessage.deserialize(
        serviceMessageSerialized
      );
      expect(finalServiceMessage.value).toHaveLength(valueLength);
    });
  });
});
