import { Parser } from 'binary-parser';
import { expectPromiseToReject } from '../_test_utils';
import RAMFError from './RAMFError';
import ServiceMessage from './ServiceMessage';

describe('ServiceMessage', () => {
  describe('serialize', () => {
    const payloadParser = new Parser()
      .endianess('little')
      .uint8('messageTypeLength')
      .string('messageType', { length: 'messageTypeLength', encoding: 'utf8' })
      .uint32('messageLength')
      .buffer('message', { length: 'messageLength' });

    test('A type with a length longer than 8 bits should be refused', async () => {
      const maxLength = 2 ** 8 - 1; // 8 bits
      const message = new ServiceMessage(
        'a'.repeat(maxLength + 1),
        Buffer.alloc(0)
      );
      await expectPromiseToReject(
        message.serialize(),
        new RAMFError('Service message type exceeds maximum length')
      );
    });

    test('A value with a length longer than 32 bits should be refused', async () => {
      const maxLength = 2 ** 32; // 32 bits
      const value = Buffer.alloc(0);
      jest.spyOn(value, 'length', 'get').mockReturnValueOnce(maxLength + 1);
      const message = new ServiceMessage('text/plain', value);
      await expectPromiseToReject(
        message.serialize(),
        new RAMFError('Service message value exceeds maximum length')
      );
    });

    test('Result should match structure defined in Relaynet Core', async () => {
      const type = 'text/plain';
      const value = Buffer.from('Hi');
      const message = new ServiceMessage(type, value);
      const messageParts = payloadParser.parse(await message.serialize());
      expect(messageParts).toHaveProperty('messageTypeLength', type.length);
      expect(messageParts).toHaveProperty('messageType', type);
      expect(messageParts).toHaveProperty('messageLength', value.byteLength);
      expect(value.equals(messageParts.message)).toBeTrue();
    });

    test('Type should be encoded in UTF-8', async () => {
      const type = 'こんにちは';
      const message = new ServiceMessage(type, Buffer.from('Hi'));
      const messageParts = payloadParser.parse(await message.serialize());
      expect(messageParts).toHaveProperty('messageType', type);
    });
  });
});
