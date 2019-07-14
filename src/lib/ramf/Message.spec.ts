/* tslint:disable:no-let max-classes-per-file */
import { Parser } from 'binary-parser';
import * as jestDateMock from 'jest-date-mock';
import { generateStubCert } from '../_test_utils';
import { generateRsaKeys } from '../crypto';
import Certificate from '../pki/Certificate';
import Message from './Message';
import Payload from './Payload';
import RAMFError from './RAMFError';

const mockUuid4 = '56e95d8a-6be2-4020-bb36-5dd0da36c181';
jest.mock('uuid4', () => {
  return {
    __esModule: true,
    default: jest.fn().mockImplementation(() => mockUuid4)
  };
});

const NON_ASCII_STRING = 'こんにちは';

class StubMessage extends Message {
  public static readonly CONCRETE_MESSAGE_TYPE_OCTET = 0x44;
  public static readonly CONCRETE_MESSAGE_VERSION_OCTET = 0x2;

  protected getConcreteMessageTypeOctet(): number {
    return StubMessage.CONCRETE_MESSAGE_TYPE_OCTET;
  }

  protected getConcreteMessageVersionOctet(): number {
    return StubMessage.CONCRETE_MESSAGE_VERSION_OCTET;
  }
}

class StubPayload extends Payload {
  public serialize(): Buffer {
    return Buffer.from('Hi');
  }
}

const payload = new StubPayload();

const PARSER = new Parser()
  .endianess('little')
  .string('magic', { length: 8, assert: 'Relaynet' })
  .uint8('formatSignature')
  .uint8('formatVersion')
  .uint16('recipientAddressLength')
  .string('recipientAddress', { length: 'recipientAddressLength' })
  .uint8('messageIdLength')
  .string('messageId', { length: 'messageIdLength', encoding: 'ascii' })
  .uint32('date');

afterEach(() => {
  jest.restoreAllMocks();
  jestDateMock.clear();
});

describe('Message', () => {
  let recipientAddress: string;
  let recipientCertificate: Certificate;
  // let senderPrivateKey: CryptoKey;
  let senderCertificate: Certificate;
  beforeAll(async () => {
    const recipientKeyPair = await generateRsaKeys();
    recipientCertificate = await generateStubCert({
      subjectPublicKey: recipientKeyPair.publicKey
    });
    recipientAddress = recipientCertificate.getAddress();

    const senderKeyPair = await generateRsaKeys();
    // senderPrivateKey = senderKeyPair.privateKey;
    senderCertificate = await generateStubCert({
      subjectPublicKey: senderKeyPair.publicKey
    });
  });

  describe('constructor', () => {
    describe('Address', () => {
      test('An address with a length of up to 10 bits should be accepted', () => {
        const address = 'a'.repeat(2 ** 10 - 1);
        const message = new StubMessage(address, senderCertificate, payload);

        expect(message.recipientAddress).toEqual(address);
      });

      test('An address with a length greater than 10 bites should be refused', () => {
        const invalidAddress = 'a'.repeat(2 ** 10);
        expect(
          () => new StubMessage(invalidAddress, senderCertificate, payload)
        ).toThrowWithMessage(
          RAMFError,
          'Recipient address exceeds maximum length'
        );
      });
    });

    describe('Id', () => {
      test('Random ids should be assigned by default', () => {
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload
        );

        expect(message.id).toEqual(mockUuid4);
      });

      test('A custom id with a length of up to 8 bits should be accepted', () => {
        const customId = 'a'.repeat(2 ** 8 - 1);
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload,
          { id: customId }
        );
        expect(message.id).toEqual(customId);
      });

      test('A custom id with a length greater than 8 bits should be refused', () => {
        const invalidId = 'a'.repeat(2 ** 8);
        expect(
          () =>
            new StubMessage(recipientAddress, senderCertificate, payload, {
              id: invalidId
            })
        ).toThrowWithMessage(RAMFError, 'Custom id exceeds maximum length');
      });
    });

    describe('Date', () => {
      test('The current date should be used by default', () => {
        const now = new Date(2019, 1, 1, 1, 1, 1, 1);
        jestDateMock.advanceTo(now);

        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload
        );

        expect(message.date).toEqual(now);
        expect(message.date.getTimezoneOffset()).toEqual(0);
      });

      test('A custom date should be accepted', () => {
        const date = new Date(2020, 1, 1, 1, 1, 1, 1);

        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload,
          { date }
        );

        expect(message.date).toEqual(date);
      });

      test('A custom date should not be before Unix epoch', () => {
        const invalidDate = new Date(1969, 11, 31, 23, 59, 59);

        expect(
          () =>
            new StubMessage(recipientAddress, senderCertificate, payload, {
              date: invalidDate
            })
        ).toThrowWithMessage(RAMFError, 'Date cannot be before Unix epoch');
      });

      test('The timestamp of a custom date should be less than 2 ^ 32', () => {
        const invalidDate = new Date(2 ** 32 * 1000);

        expect(
          () =>
            new StubMessage(recipientAddress, senderCertificate, payload, {
              date: invalidDate
            })
        ).toThrowWithMessage(
          RAMFError,
          'Date timestamp cannot be represented with 32 bits'
        );
      });

      test('A custom date should be stored in UTC', () => {
        const date = new Date('01 Jan 2019 12:00:00 GMT+11:00');

        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload,
          { date }
        );

        expect(message.date).toEqual(new Date('01 Jan 2019 01:00:00 GMT'));
      });
    });

    describe('TTL', () => {
      test.todo('TTL should default to 5 minutes');

      test.todo('A custom TTL should be accepted');

      test.todo('A custom TTL of zero should be accepted');

      test.todo('A custom TTL should not be negative');

      test.todo('A custom TTL should be less than 2 ^ 24');
    });
  });

  describe('serialize', () => {
    describe('Format signature', () => {
      let stubMessage: StubMessage;
      beforeAll(() => {
        stubMessage = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload
        );
      });

      test('The ASCII string "Relaynet" should be at the start', async () => {
        const messageSerialized = await stubMessage.serialize();
        const staticPrefixBuffer = Buffer.from(messageSerialized, 0, 8);
        expect(staticPrefixBuffer.toString('ascii')).toEqual('Relaynet');
      });

      test('The concrete message type should be represented with an octet', async () => {
        const messageSerialized = await stubMessage.serialize();
        const concreteMessageBuffer = Buffer.from(messageSerialized, 8, 1);
        expect(concreteMessageBuffer.readUInt8(0)).toEqual(
          StubMessage.CONCRETE_MESSAGE_TYPE_OCTET
        );
      });

      test('The concrete message version should be at the end', async () => {
        const messageSerialized = await stubMessage.serialize();
        const concreteMessageBuffer = Buffer.from(messageSerialized, 9, 1);
        expect(concreteMessageBuffer.readUInt8(0)).toEqual(
          StubMessage.CONCRETE_MESSAGE_VERSION_OCTET
        );
      });
    });

    describe('Recipient address', () => {
      test('Address should be serialized with length prefix', async () => {
        const address = recipientCertificate.getAddress();
        const stubMessage = new StubMessage(
          address,
          senderCertificate,
          payload
        );

        const messageSerialized = await stubMessage.serialize();
        const messageDeserialized = PARSER.parse(
          Buffer.from(messageSerialized)
        );
        expect(messageDeserialized).toHaveProperty(
          'recipientAddressLength',
          address.length
        );
        expect(messageDeserialized).toHaveProperty('recipientAddress', address);
      });

      test('Non-ASCII recipient addresses should be UTF-8 encoded', async () => {
        const stubMessage = new StubMessage(
          NON_ASCII_STRING,
          senderCertificate,
          payload
        );

        const messageSerialized = await stubMessage.serialize();
        const messageDeserialized = PARSER.parse(
          Buffer.from(messageSerialized)
        );
        expect(messageDeserialized).toHaveProperty(
          'recipientAddress',
          NON_ASCII_STRING
        );
      });
    });

    describe('Message id', () => {
      test('Id should be serialized with a length prefix', async () => {
        const stubMessage = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload
        );

        const messageSerialized = await stubMessage.serialize();
        const messageDeserialized = PARSER.parse(
          Buffer.from(messageSerialized)
        );
        expect(messageDeserialized).toHaveProperty(
          'messageIdLength',
          mockUuid4.length
        );
        expect(messageDeserialized).toHaveProperty('messageId', stubMessage.id);
      });

      test('Id should be ASCII-encoded', async () => {
        const stubMessage = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload,
          { id: NON_ASCII_STRING }
        );

        const messageSerialized = await stubMessage.serialize();
        const messageDeserialized = PARSER.parse(
          Buffer.from(messageSerialized)
        );
        const expectedId = Buffer.from(NON_ASCII_STRING, 'ascii').toString(
          'ascii'
        );
        expect(messageDeserialized).toHaveProperty('messageId', expectedId);
      });
    });

    describe('Date', () => {
      test('Date should be serialized as 32-bit unsigned integer', async () => {
        const stubMessage = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload
        );

        const messageSerialized = await stubMessage.serialize();
        const messageDeserialized = PARSER.parse(
          Buffer.from(messageSerialized)
        );
        const expectedTimestamp = Math.floor(stubMessage.date.getTime() / 1000);
        expect(messageDeserialized).toHaveProperty('date', expectedTimestamp);
      });
    });

    describe('TTL', () => {
      test.todo('TTL should be serialized as 24-bit unsigned integer');
    });
  });
});
