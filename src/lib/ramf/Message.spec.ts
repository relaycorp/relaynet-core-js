/* tslint:disable:no-let max-classes-per-file */
import { Parser } from 'binary-parser';
import bufferToArray from 'buffer-to-arraybuffer';
import * as jestDateMock from 'jest-date-mock';
import { expectPromiseToReject, generateStubCert } from '../_test_utils';
import * as cms from '../cms';
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

const NON_ASCII_STRING = '❤こんにちは';

class StubMessage extends Message<StubPayload> {
  public static readonly CONCRETE_MESSAGE_TYPE_OCTET = 0x44;
  public static readonly CONCRETE_MESSAGE_VERSION_OCTET = 0x2;

  protected getConcreteMessageTypeOctet(): number {
    return StubMessage.CONCRETE_MESSAGE_TYPE_OCTET;
  }

  protected getConcreteMessageVersionOctet(): number {
    return StubMessage.CONCRETE_MESSAGE_VERSION_OCTET;
  }
}

class StubPayload implements Payload {
  public static readonly BUFFER = bufferToArray(Buffer.from('Hi'));

  public serialize(): ArrayBuffer {
    return StubPayload.BUFFER;
  }
}

const payload = new StubPayload();

const PARSER = new Parser()
  .endianess('little')
  .string('magic', { length: 8, assert: 'Relaynet' })
  .uint8('concreteMessageSignature')
  .uint8('concreteMessageVersion')
  .uint16('recipientAddressLength')
  .string('recipientAddress', { length: 'recipientAddressLength' })
  .uint8('messageIdLength')
  .string('messageId', { length: 'messageIdLength', encoding: 'ascii' })
  .uint32('date')
  .buffer('ttlBuffer', { length: 3 })
  .uint32('payloadLength')
  .buffer('payload', { length: 'payloadLength' })
  .uint16('signatureLength')
  .buffer('signature', { length: 'signatureLength' });

afterEach(() => {
  jest.restoreAllMocks();
  jestDateMock.clear();
});

describe('Message', () => {
  let recipientAddress: string;
  let recipientCertificate: Certificate;
  let recipientPrivateKey: CryptoKey;
  let senderPrivateKey: CryptoKey;
  let senderCertificate: Certificate;
  beforeAll(async () => {
    const recipientKeyPair = await generateRsaKeys();
    recipientCertificate = await generateStubCert({
      subjectPublicKey: recipientKeyPair.publicKey
    });
    recipientAddress = recipientCertificate.getAddress();
    recipientPrivateKey = recipientKeyPair.privateKey;

    const senderKeyPair = await generateRsaKeys();
    senderPrivateKey = senderKeyPair.privateKey;
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

      test('Multi-byte characters should be accounted for in length validation', () => {
        const invalidAddress = '❤'.repeat(2 ** 10 - 1);
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
      test('5 minutes should be the default TTL', () => {
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload
        );

        expect(message.ttl).toEqual(5 * 60);
      });

      test('A custom TTL under 2^24 should be accepted', () => {
        const ttl = 2 ** 24 - 1;
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload,
          { ttl }
        );

        expect(message.ttl).toEqual(ttl);
      });

      test('A custom TTL of zero should be accepted', () => {
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload,
          { ttl: 0 }
        );

        expect(message.ttl).toEqual(0);
      });

      test('A custom TTL should not be negative', () => {
        expect(
          () =>
            new StubMessage(recipientAddress, senderCertificate, payload, {
              ttl: -1
            })
        ).toThrowWithMessage(RAMFError, 'TTL cannot be negative');
      });

      test('A custom TTL should be less than 2 ^ 24', () => {
        expect(
          () =>
            new StubMessage(recipientAddress, senderCertificate, payload, {
              ttl: 2 ** 24
            })
        ).toThrowWithMessage(RAMFError, 'TTL must be less than 2^24');
      });
    });

    describe('Sender certificate chain', () => {
      test('Sender certificate chain should be empty by default', () => {
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload
        );

        expect(message.senderCertificateChain).toHaveProperty('size', 0);
      });

      test('A custom sender certificate chain should be accepted', async () => {
        const chain = new Set([await generateStubCert()]);
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload,
          { senderCertificateChain: chain }
        );

        expect(message.senderCertificateChain).toEqual(chain);
      });
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
        const messageSerialized = await stubMessage.serialize(
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = PARSER.parse(Buffer.from(messageSerialized));
        expect(messageParts).toHaveProperty('magic', 'Relaynet');
      });

      test('The concrete message type should be represented with an octet', async () => {
        const messageSerialized = await stubMessage.serialize(
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = PARSER.parse(Buffer.from(messageSerialized));
        expect(messageParts).toHaveProperty(
          'concreteMessageSignature',
          StubMessage.CONCRETE_MESSAGE_TYPE_OCTET
        );
      });

      test('The concrete message version should be at the end', async () => {
        const messageSerialized = await stubMessage.serialize(
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = PARSER.parse(Buffer.from(messageSerialized));
        expect(messageParts).toHaveProperty(
          'concreteMessageVersion',
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

        const messageSerialized = await stubMessage.serialize(
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = PARSER.parse(Buffer.from(messageSerialized));
        expect(messageParts).toHaveProperty(
          'recipientAddressLength',
          address.length
        );
        expect(messageParts).toHaveProperty('recipientAddress', address);
      });

      test('Non-ASCII recipient addresses should be UTF-8 encoded', async () => {
        const stubMessage = new StubMessage(
          NON_ASCII_STRING,
          senderCertificate,
          payload
        );

        const messageSerialized = await stubMessage.serialize(
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = PARSER.parse(Buffer.from(messageSerialized));
        expect(messageParts).toHaveProperty(
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

        const messageSerialized = await stubMessage.serialize(
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = PARSER.parse(Buffer.from(messageSerialized));
        expect(messageParts).toHaveProperty(
          'messageIdLength',
          mockUuid4.length
        );
        expect(messageParts).toHaveProperty('messageId', stubMessage.id);
      });

      test('Id should be ASCII-encoded', async () => {
        const stubMessage = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload,
          { id: NON_ASCII_STRING }
        );

        const messageSerialized = await stubMessage.serialize(
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = PARSER.parse(Buffer.from(messageSerialized));
        const expectedId = Buffer.from(NON_ASCII_STRING, 'ascii').toString(
          'ascii'
        );
        expect(messageParts).toHaveProperty('messageId', expectedId);
      });
    });

    describe('Date', () => {
      test('Date should be serialized as 32-bit unsigned integer', async () => {
        const stubMessage = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload
        );

        const messageSerialized = await stubMessage.serialize(
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = PARSER.parse(Buffer.from(messageSerialized));
        const expectedTimestamp = Math.floor(stubMessage.date.getTime() / 1000);
        expect(messageParts).toHaveProperty('date', expectedTimestamp);
      });
    });

    describe('TTL', () => {
      test('TTL should be serialized as 24-bit unsigned integer', async () => {
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload
        );

        const messageSerialized = await message.serialize(
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = PARSER.parse(Buffer.from(messageSerialized));
        const ttlDeserialized = messageParts.ttlBuffer;
        expect(ttlDeserialized.readUIntLE(0, 3)).toEqual(message.ttl);
      });
    });

    describe('Payload', () => {
      test('Payload should be encrypted', async () => {
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload
        );
        jest.spyOn(cms, 'encrypt');

        const messageSerialized = await message.serialize(
          senderPrivateKey,
          recipientCertificate
        );

        expect(cms.encrypt).toBeCalledTimes(1);
        expect(cms.encrypt).toBeCalledWith(
          StubPayload.BUFFER,
          recipientCertificate,
          undefined
        );

        const messageParts = PARSER.parse(Buffer.from(messageSerialized));
        const payloadCiphertext = messageParts.payload;
        expect(
          await cms.decrypt(
            bufferToArray(payloadCiphertext),
            recipientPrivateKey
          )
        ).toEqual(StubPayload.BUFFER);
      });

      test('Encryption options should be honoured', async () => {
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload
        );
        jest.spyOn(cms, 'encrypt');

        const encryptionOptions = { aesKeySize: 256 };
        await message.serialize(
          senderPrivateKey,
          recipientCertificate,
          encryptionOptions
        );

        expect(cms.encrypt).toBeCalledTimes(1);
        expect(cms.encrypt).toBeCalledWith(
          StubPayload.BUFFER,
          recipientCertificate,
          encryptionOptions
        );
      });
    });

    describe('Signature', () => {
      let senderCertificateChain: Set<Certificate>;
      let serialization: Buffer;
      let cmsSignArgs: readonly any[];
      let signature: Buffer;
      beforeAll(async () => {
        senderCertificateChain = new Set([await generateStubCert()]);
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload,
          { senderCertificateChain }
        );

        jest.spyOn(cms, 'sign');
        serialization = Buffer.from(
          await message.serialize(senderPrivateKey, recipientCertificate)
        );
        expect(cms.sign).toBeCalledTimes(1);
        // @ts-ignore
        cmsSignArgs = cms.sign.mock.calls[0];

        const messageParts = PARSER.parse(serialization);
        signature = messageParts.signature;
      });

      test('Plaintext should be preceding RAMF message octets', () => {
        const plaintext = Buffer.from(cmsSignArgs[0]);
        const expectedPlaintextLength =
          serialization.length - 2 - signature.length;
        const expectedPlaintext = serialization.slice(
          0,
          expectedPlaintextLength
        );

        expect(plaintext.equals(expectedPlaintext)).toBeTrue();
      });

      test('The sender private key should be used to generate signature', () => {
        const actualSenderPrivateKey = cmsSignArgs[1];

        expect(actualSenderPrivateKey).toBe(senderPrivateKey);
      });

      test('The sender certificate should be used to generate signature', () => {
        const actualSenderCertificate = cmsSignArgs[2];

        expect(actualSenderCertificate).toBe(senderCertificate);
      });

      test('Sender certificate should be attached', () => {
        const attachedCertificates = cmsSignArgs[3];

        expect(attachedCertificates).toContain(senderCertificate);
      });

      test('Sender certificate chain should be attached', () => {
        const attachedCertificates = cmsSignArgs[3];

        for (const cert of senderCertificateChain) {
          expect(attachedCertificates).toContain(cert);
        }
      });

      test('Signature should be less than 16 KiB', async () => {
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload
        );
        const mockSignature = new ArrayBuffer(0);
        jest.spyOn(mockSignature, 'byteLength', 'get').mockReturnValue(2 ** 16);
        jest.spyOn(cms, 'sign').mockReturnValue(Promise.resolve(mockSignature));

        await expectPromiseToReject(
          message.serialize(senderPrivateKey, recipientCertificate),
          new RAMFError('Resulting signature must be less than 16 KiB')
        );
      });

      test('SHA-256 should be used by default', () => {
        const signatureOptions = cmsSignArgs[4];

        expect(signatureOptions).toBe(undefined);
      });

      test.each([['SHA-384', 'SHA-512']])(
        '%s should also be supported',
        async hashingAlgorithmName => {
          const message = new StubMessage(
            recipientAddress,
            senderCertificate,
            payload
          );

          jest.spyOn(cms, 'sign');
          await message.serialize(senderPrivateKey, recipientCertificate, {
            hashingAlgorithmName
          });
          expect(cms.sign).toBeCalledTimes(1);
          // @ts-ignore
          const signatureArgs = cms.sign.mock.calls[0];
          expect(signatureArgs[4]).toEqual({ hashingAlgorithmName });
        }
      );
    });
  });
});
