/* tslint:disable:no-let */
import { Parser } from 'binary-parser';
import bufferToArray from 'buffer-to-arraybuffer';
import * as jestDateMock from 'jest-date-mock';
import { SmartBuffer } from 'smart-buffer';

import {
  expectBuffersToEqual,
  expectPkijsValuesToBeEqual,
  expectPromiseToReject,
  generateStubCert,
  getMockContext,
  getPromiseRejection,
} from '../_test_utils';
import * as cmsSignedData from '../crypto_wrappers/cms/signedData';
import { generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { NON_ASCII_STRING, StubMessage } from './_test_utils';
import RAMFSyntaxError from './RAMFSyntaxError';
import RAMFValidationError from './RAMFValidationError';
import { deserialize, MessageFields, serialize } from './serialization';

const PAYLOAD = Buffer.from('Hi');

const STUB_DATE = new Date(2014, 1, 19);
STUB_DATE.setMilliseconds(0); // There should be tests covering rounding when there are milliseconds

const stubConcreteMessageTypeOctet = 0x44;
const stubConcreteMessageVersionOctet = 0x2;

const MESSAGE_PARSER = new Parser()
  .endianess('little')
  .string('magic', { length: 8, assert: 'Relaynet' })
  .uint8('concreteMessageType')
  .uint8('concreteMessageVersion')
  .uint16('recipientAddressLength')
  .string('recipientAddress', { length: 'recipientAddressLength' })
  .uint8('idLength')
  .string('id', { length: 'idLength', encoding: 'ascii' })
  .uint32('dateTimestamp')
  .buffer('ttlBuffer', { length: 3 })
  .uint32('payloadLength')
  .buffer('payload', { length: 'payloadLength' })
  .uint16('signatureLength')
  .buffer('signature', { length: 'signatureLength' });

const mockStubUuid4 = '56e95d8a-6be2-4020-bb36-5dd0da36c181';
jest.mock('uuid4', () => {
  return {
    __esModule: true,
    default: jest.fn().mockImplementation(() => mockStubUuid4),
  };
});

afterEach(() => {
  jest.restoreAllMocks();
  jestDateMock.clear();
});

describe('MessageSerializer', () => {
  let recipientAddress: string;
  let senderPrivateKey: CryptoKey;
  let senderCertificate: Certificate;
  beforeAll(async () => {
    const yesterday = new Date(STUB_DATE);
    yesterday.setDate(yesterday.getDate() - 1);
    const tomorrow = new Date(STUB_DATE);
    tomorrow.setDate(tomorrow.getDate() + 1);
    const certificateAttributes = { validityStartDate: yesterday, validityEndDate: tomorrow };

    recipientAddress = '0123456789';

    const senderKeyPair = await generateRSAKeyPair();
    senderPrivateKey = senderKeyPair.privateKey;
    senderCertificate = await generateStubCert({
      attributes: certificateAttributes,
      subjectPublicKey: senderKeyPair.publicKey,
    });
  });

  beforeEach(() => {
    jestDateMock.advanceTo(STUB_DATE);
  });

  describe('serialize', () => {
    describe('Format signature', () => {
      let stubMessage: StubMessage;
      beforeAll(() => {
        stubMessage = new StubMessage(recipientAddress, senderCertificate, PAYLOAD);
      });

      test('The ASCII string "Relaynet" should be at the start', async () => {
        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const messageParts = parseMessage(messageSerialized);
        expect(messageParts).toHaveProperty('magic', 'Relaynet');
      });

      test('The concrete message type should be represented with an octet', async () => {
        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const messageParts = parseMessage(messageSerialized);
        expect(messageParts).toHaveProperty('concreteMessageType', stubConcreteMessageTypeOctet);
      });

      test('The concrete message version should be at the end', async () => {
        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const messageParts = parseMessage(messageSerialized);
        expect(messageParts).toHaveProperty(
          'concreteMessageVersion',
          stubConcreteMessageVersionOctet,
        );
      });
    });

    describe('Recipient address', () => {
      test('Address should be serialized with length prefix', async () => {
        const stubMessage = new StubMessage(recipientAddress, senderCertificate, PAYLOAD);

        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const messageParts = parseMessage(messageSerialized);
        expect(messageParts).toHaveProperty('recipientAddressLength', recipientAddress.length);
        expect(messageParts).toHaveProperty('recipientAddress', recipientAddress);
      });

      test('Address should be representable with 10 bits', async () => {
        const address = 'a'.repeat(2 ** 10 - 1);
        const stubMessage = new StubMessage(address, senderCertificate, PAYLOAD);

        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const messageParts = parseMessage(messageSerialized);
        expect(messageParts).toHaveProperty('recipientAddress', address);
      });

      test('Address should not exceed 10 bits length', async () => {
        const invalidAddress = 'a'.repeat(2 ** 10);
        const stubMessage = new StubMessage(invalidAddress, senderCertificate, PAYLOAD);

        await expectPromiseToReject(
          serialize(
            stubMessage,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          ),
          new RAMFSyntaxError('Recipient address exceeds maximum length'),
        );
      });

      test('Non-ASCII addresses should be UTF-8 encoded', async () => {
        const stubMessage = new StubMessage(NON_ASCII_STRING, senderCertificate, PAYLOAD);

        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const messageParts = parseMessage(messageSerialized);
        expect(messageParts).toHaveProperty('recipientAddress', NON_ASCII_STRING);
      });

      test('Multi-byte characters should be accounted for in length validation', async () => {
        const invalidAddress = '❤'.repeat(2 ** 10 - 1);
        const stubMessage = new StubMessage(invalidAddress, senderCertificate, PAYLOAD);

        await expectPromiseToReject(
          serialize(
            stubMessage,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          ),
          new RAMFSyntaxError('Recipient address exceeds maximum length'),
        );
      });
    });

    describe('Message id', () => {
      test('Id should be up to 8 bits long', async () => {
        const idLength = 2 ** 8 - 1;
        const id = 'a'.repeat(idLength);
        const stubMessage = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, { id });

        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const messageParts = parseMessage(messageSerialized);
        expect(messageParts).toHaveProperty('idLength', idLength);
        expect(messageParts).toHaveProperty('id', stubMessage.id);
      });

      test('A custom id with a length greater than 8 bits should be refused', async () => {
        const id = 'a'.repeat(2 ** 8);
        const stubMessage = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, { id });

        await expectPromiseToReject(
          serialize(
            stubMessage,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          ),
          new RAMFSyntaxError('Custom id exceeds maximum length'),
        );
      });

      test('Id should be ASCII-encoded', async () => {
        const stubMessage = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
          id: NON_ASCII_STRING,
        });

        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const messageParts = parseMessage(messageSerialized);
        const expectedId = Buffer.from(NON_ASCII_STRING, 'ascii').toString('ascii');
        expect(messageParts).toHaveProperty('id', expectedId);
      });
    });

    describe('Date', () => {
      test('Date should be serialized as 32-bit unsigned integer', async () => {
        const stubMessage = new StubMessage(recipientAddress, senderCertificate, PAYLOAD);

        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const messageParts = parseMessage(messageSerialized);
        const expectedTimestamp = Math.floor(stubMessage.date.getTime() / 1000);
        expect(messageParts).toHaveProperty('dateTimestamp', expectedTimestamp);
      });

      test('Date should not be before Unix epoch', async () => {
        // Don't pass the number of seconds since epoch directly because the local timezone would
        // be used
        const invalidDate = new Date('1969-12-31T23:59:59.000Z');
        const stubMessage = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
          date: invalidDate,
        });

        await expectPromiseToReject(
          serialize(
            stubMessage,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          ),
          new RAMFSyntaxError('Date cannot be before Unix epoch'),
        );
      });

      test('Timestamp should be less than 2 ^ 32', async () => {
        // Don't pass the number of seconds since epoch directly because the local timezone would
        // be used
        const invalidDate = new Date('2106-02-07T06:28:16.000Z'); // 2 ^ 32 seconds since epoch
        const stubMessage = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
          date: invalidDate,
        });

        await expectPromiseToReject(
          serialize(
            stubMessage,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          ),
          new RAMFSyntaxError('Date timestamp cannot be represented with 32 bits'),
        );
      });

      test('Date should be serialized as UTC', async () => {
        const date = new Date('01 Jan 2019 12:00:00 GMT+11:00');
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, { date });

        const messageSerialized = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        const messageParts = parseMessage(messageSerialized);
        expect(messageParts).toHaveProperty('dateTimestamp', date.getTime() / 1_000);
      });
    });

    describe('TTL', () => {
      test('TTL should be serialized as 24-bit unsigned integer', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD);

        const messageSerialized = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const messageParts = parseMessage(messageSerialized);
        expect(parse24BitNumber(messageParts.ttlBuffer)).toEqual(message.ttl);
      });

      test('TTL of zero should be accepted', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, { ttl: 0 });

        const messageSerialized = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        const messageParts = parseMessage(messageSerialized);
        expect(parse24BitNumber(messageParts.ttlBuffer)).toEqual(0);
      });

      test('TTL should not be negative', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
          ttl: -1,
        });
        await expectPromiseToReject(
          serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          ),
          new RAMFSyntaxError('TTL cannot be negative'),
        );
      });

      test('TTL should not be more than 24 bits long', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
          ttl: 2 ** 24,
        });
        await expectPromiseToReject(
          serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          ),
          new RAMFSyntaxError('TTL must be less than 2^24'),
        );
      });
    });

    test('Payload should be serialized as is', async () => {
      const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD);

      const messageSerialized = await serialize(
        message,
        stubConcreteMessageTypeOctet,
        stubConcreteMessageVersionOctet,
        senderPrivateKey,
      );

      const messageParts = parseMessage(messageSerialized);
      expectBuffersToEqual(messageParts.payload, PAYLOAD);
    });

    describe('Signature', () => {
      let senderCertificateChain: Set<Certificate>;
      let messageSerialized: ArrayBuffer;
      let cmsSignArgs: readonly any[];
      let signature: Buffer;
      beforeAll(async () => {
        senderCertificateChain = new Set([await generateStubCert()]);
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
          senderCertificateChain,
        });

        jest.spyOn(cmsSignedData, 'sign');
        messageSerialized = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        expect(cmsSignedData.sign).toBeCalledTimes(1);
        // @ts-ignore
        cmsSignArgs = cmsSignedData.sign.mock.calls[0];

        const messageParts = parseMessage(messageSerialized);
        signature = messageParts.signature;
      });

      test('Plaintext should be preceding RAMF message octets', () => {
        const plaintext = Buffer.from(cmsSignArgs[0]);
        const expectedPlaintextLength = messageSerialized.byteLength - 2 - signature.length;
        const expectedPlaintext = Buffer.from(messageSerialized, 0, expectedPlaintextLength);

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

      test('Signature should be less than 14 bits long', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD);
        const mockSignature = new ArrayBuffer(0);
        const signatureLength = 2 ** 14;
        jest.spyOn(mockSignature, 'byteLength', 'get').mockReturnValue(signatureLength);
        jest.spyOn(cmsSignedData, 'sign').mockReturnValue(Promise.resolve(mockSignature));

        await expectPromiseToReject(
          serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          ),
          new RAMFSyntaxError(
            `Signature length is ${signatureLength} but maximum is ${2 ** 14 - 1}`,
          ),
        );
      });

      test('SHA-256 should be used by default', () => {
        const signatureOptions = cmsSignArgs[4];

        expect(signatureOptions).toBe(undefined);
      });

      test.each([['SHA-384', 'SHA-512']])(
        '%s should also be supported',
        async hashingAlgorithmName => {
          const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD);

          jest.spyOn(cmsSignedData, 'sign');
          await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
            {
              hashingAlgorithmName,
            },
          );
          expect(cmsSignedData.sign).toBeCalledTimes(1);
          // @ts-ignore
          const signatureArgs = cmsSignedData.sign.mock.calls[0];
          expect(signatureArgs[4]).toEqual({ hashingAlgorithmName });
        },
      );
    });
  });

  describe('deserialize', () => {
    describe('Format signature', () => {
      test('Input should be refused if it does not start with "Relaynet"', async () => {
        const serialization = bufferToArray(Buffer.from('Relaycorp'));
        await expectPromiseToReject(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
          new RAMFSyntaxError('Serialization is not a valid RAMF message: Relaynet is not defined'),
        );
      });

      test('A non-matching concrete message type should be refused', async () => {
        const altMessage = new StubMessage(recipientAddress, senderCertificate, PAYLOAD);
        const serialization = await serialize(
          altMessage,
          stubConcreteMessageTypeOctet + 1,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        await expectPromiseToReject(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
          new RAMFSyntaxError('Expected concrete message type 0x44 but got 0x45'),
        );
      });

      test('A non-matching concrete message version should be refused', async () => {
        const altMessage = new StubMessage(recipientAddress, senderCertificate, PAYLOAD);
        const serialization = await serialize(
          altMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet + 1,
          senderPrivateKey,
        );

        await expectPromiseToReject(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
          new RAMFSyntaxError('Expected concrete message version 0x2 but got 0x3'),
        );
      });
    });

    describe('Recipient address', () => {
      test('Address should be serialized with length prefix', async () => {
        const address = 'a'.repeat(2 ** 10 - 1);
        const message = new StubMessage(address, senderCertificate, PAYLOAD);
        const serialization = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const deserialization = await deserialize(
          serialization,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        );
        expect(deserialization.recipientAddress).toEqual(address);
      });

      test('Length prefix should not exceed 10 bits', async () => {
        const address = 'a'.repeat(2 ** 10);
        const messageSerialized = await serializeWithoutValidation({ address });
        await expectPromiseToReject(
          deserialize(
            messageSerialized,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
          new RAMFSyntaxError('Recipient address exceeds maximum length'),
        );
      });

      test('Address should be UTF-8 encoded', async () => {
        const address = `scheme://${NON_ASCII_STRING}.com`;
        const message = new StubMessage(address, senderCertificate, PAYLOAD);
        const serialization = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const deserialization = await deserialize(
          serialization,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        );
        expect(deserialization.recipientAddress).toEqual(address);
      });
    });

    describe('Message id', () => {
      test('Id should be serialized with length prefix', async () => {
        const id = 'a'.repeat(2 ** 8 - 1);
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, { id });
        const serialization = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const deserialization = await deserialize(
          serialization,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        );
        expect(deserialization.id).toEqual(id);
      });

      test('Id should be ASCII-encoded', async () => {
        const id = NON_ASCII_STRING;
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, { id });
        const serialization = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const deserialization = await deserialize(
          serialization,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        );
        const expectedId = Buffer.from(id, 'ascii').toString('ascii');
        expect(deserialization.id).toEqual(expectedId);
      });
    });

    describe('Date', () => {
      test('Date should be serialized as 32-bit unsigned integer', async () => {
        const maxTimestampSec = 2 ** 31;
        const stubDate = new Date(maxTimestampSec * 1_000);
        const stubSenderKeyPair = await generateRSAKeyPair();
        const stubSenderCertificate = await generateStubCert({
          attributes: {
            validityEndDate: stubDate,
            validityStartDate: new Date(stubDate.getDate() - 1_000),
          },
          subjectPublicKey: stubSenderKeyPair.publicKey,
        });
        const message = new StubMessage(recipientAddress, stubSenderCertificate, PAYLOAD, {
          date: stubDate,
        });
        const serialization = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          stubSenderKeyPair.privateKey,
        );

        jestDateMock.advanceTo(stubDate);
        const deserialization = await deserialize(
          serialization,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        );

        expect(deserialization.date).toEqual(stubDate);
      });

      test('Date equal to the current date should be accepted', async () => {
        const stubDate = new Date(
          senderCertificate.pkijsCertificate.notAfter.value.getTime() - 1_000,
        );
        stubDate.setSeconds(0, 0);
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
          date: stubDate,
        });
        const serialization = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        jestDateMock.advanceTo(stubDate);
        const deserialization = await deserialize(
          serialization,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        );

        expect(deserialization.date).toEqual(stubDate);
      });

      test('Date should not be in the future', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
          date: new Date(STUB_DATE.getTime() + 1_000),
        });
        const serialization = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        jestDateMock.advanceTo(STUB_DATE);
        await expectPromiseToReject(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
          new RAMFValidationError('Message date is in the future', parseMessage(serialization)),
        );
      });

      test('Date should not be before start date of sender certificate', async () => {
        const certStartDate = senderCertificate.pkijsCertificate.notBefore.value;
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
          date: new Date(certStartDate.getTime() - 1_000),
        });
        const serialization = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        jestDateMock.advanceTo(certStartDate);
        await expectPromiseToReject(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
          new RAMFValidationError(
            'Message was created before the sender certificate was valid',
            parseMessage(serialization),
          ),
        );
      });

      test('Date may be at the expiry date of sender certificate', async () => {
        const certEndDate = senderCertificate.pkijsCertificate.notAfter.value;
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
          date: certEndDate,
        });
        const serialization = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        jestDateMock.advanceTo(message.date);
        const deserialization = await deserialize(
          serialization,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        );

        const expectedDate = new Date(certEndDate);
        expectedDate.setMilliseconds(0);
        expect(deserialization.date).toEqual(expectedDate);
      });

      test('Date should not be after expiry date of sender certificate', async () => {
        const certEndDate = senderCertificate.pkijsCertificate.notAfter.value;
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
          date: new Date(certEndDate.getTime() + 1_000),
        });
        const serialization = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        jestDateMock.advanceTo(message.date);
        await expectPromiseToReject(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
          new RAMFValidationError(
            'Message was created after the sender certificate expired',
            parseMessage(serialization),
          ),
        );
      });
    });

    describe('TTL', () => {
      test('TTL should be serialized as 24-bit unsigned integer', async () => {
        const ttl = 2 ** 24 - 1;
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, { ttl });
        const serialization = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        const deserialization = await deserialize(
          serialization,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        );

        expect(deserialization.ttl).toEqual(ttl);
      });

      test('TTL matching current time should be accepted', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
          date: senderCertificate.pkijsCertificate.notBefore.value,
          ttl: 1,
        });
        const serialization = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        const currentDate = new Date(message.date);
        currentDate.setSeconds(currentDate.getSeconds() + message.ttl);
        currentDate.setMilliseconds(1); // Should be greater than zero so we can test rounding too
        jestDateMock.advanceTo(currentDate);
        await expect(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        ).toResolve();
      });

      test('TTL in the past should not be accepted', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
          ttl: 1,
        });
        const serialization = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        jestDateMock.advanceTo(message.date.getTime() + (message.ttl + 1) * 1_000);
        await expectPromiseToReject(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
          new RAMFValidationError('Message already expired', parseMessage(serialization)),
        );
      });
    });

    test('Payload should be serialized with length prefix', async () => {
      const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD);
      const messageSerialized = await serialize(
        message,
        stubConcreteMessageTypeOctet,
        stubConcreteMessageVersionOctet,
        senderPrivateKey,
      );

      const messageDeserialized = await deserialize(
        messageSerialized,
        stubConcreteMessageTypeOctet,
        stubConcreteMessageVersionOctet,
        StubMessage,
      );

      expect(messageDeserialized.payloadSerialized).toEqual(PAYLOAD);
    });

    describe('Signature', () => {
      test('Signature should be accepted if valid', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD);
        jest.spyOn(cmsSignedData, 'sign');
        const messageSerialized = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        jest.spyOn(cmsSignedData, 'verifySignature');
        await deserialize(
          messageSerialized,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        );

        const signatureCiphertext = await getMockContext(cmsSignedData.sign).results[0].value;
        const signaturePlaintext = messageSerialized.slice(
          0,
          messageSerialized.byteLength - signatureCiphertext.length - 2,
        );
        expect(cmsSignedData.verifySignature).toBeCalledTimes(1);
        expect(cmsSignedData.verifySignature).toBeCalledWith(
          signatureCiphertext,
          signaturePlaintext,
        );
      });

      test('Signature should not be accepted if invalid', async () => {
        const signerKeyPair = await generateRSAKeyPair();
        const signerCertificate = await generateStubCert({
          subjectPublicKey: signerKeyPair.publicKey,
        });
        const invalidSignature = await cmsSignedData.sign(
          bufferToArray(Buffer.from('Hello world')),
          signerKeyPair.privateKey,
          signerCertificate,
        );

        const messageSerialized = await serializeWithoutValidation({}, invalidSignature);

        const error = await getPromiseRejection<RAMFValidationError>(
          deserialize(
            messageSerialized,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        );
        expect(error).toBeInstanceOf(RAMFValidationError);
        expect(error.message).toEqual(
          'Invalid RAMF message signature: Invalid signature: ' +
            'Unable to find signer certificate (PKI.js code: 3)',
        );
      });

      test('Parsed message should be included in validation exception', async () => {
        const signerKeyPair = await generateRSAKeyPair();
        const signerCertificate = await generateStubCert({
          subjectPublicKey: signerKeyPair.publicKey,
        });
        const invalidSignature = await cmsSignedData.sign(
          bufferToArray(Buffer.from('Hello world')),
          signerKeyPair.privateKey,
          signerCertificate,
        );

        const id = 'This is the id. Yup.';
        const messageSerialized = await serializeWithoutValidation({ id }, invalidSignature);

        const error = await getPromiseRejection<RAMFValidationError>(
          deserialize(
            messageSerialized,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        );
        expect(error.invalidMessageFields).toHaveProperty('id', id);
      });

      test('Sender certificate should be extracted from signature', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD);
        const messageSerialized = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        const messageDeserialized = await deserialize(
          messageSerialized,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        );

        expectPkijsValuesToBeEqual(
          messageDeserialized.senderCertificate.pkijsCertificate,
          senderCertificate.pkijsCertificate,
        );
      });

      test('Sender certificate chain should be extracted from signature', async () => {
        const caCertificate = await generateStubCert();
        const messageSerialized = await serializeWithoutValidation({});

        jest.spyOn(cmsSignedData, 'verifySignature').mockImplementationOnce(async () => ({
          signerCertificate: senderCertificate,
          signerCertificateChain: [senderCertificate, caCertificate],
        }));
        const { senderCertificateChain } = await deserialize(
          messageSerialized,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        );

        expect(senderCertificateChain).toEqual(new Set([senderCertificate, caCertificate]));
      });

      test('Length prefix should be less than 14 bits long', async () => {
        const signatureLength = 2 ** 14;
        const signatureBuffer = bufferToArray(Buffer.from('a'.repeat(signatureLength)));
        const messageSerialized = await serializeWithoutValidation({}, signatureBuffer);

        await expectPromiseToReject(
          deserialize(
            messageSerialized,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
          new RAMFSyntaxError(
            `Signature length is ${signatureLength} but maximum is ${2 ** 14 - 1}`,
          ),
        );
      });
    });
  });

  async function serializeWithoutValidation(
    {
      address = 'random address',
      date = new Date(),
      id = 'random id',
      messageType = stubConcreteMessageTypeOctet,
      messageVersion = stubConcreteMessageVersionOctet,
      payloadBuffer = PAYLOAD,
      ttl = 1,
    },
    signature?: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    const serialization = new SmartBuffer();

    serialization.writeString('Relaynet');
    serialization.writeUInt8(messageType);
    serialization.writeUInt8(messageVersion);

    serialization.writeUInt16LE(Buffer.byteLength(address));
    serialization.writeString(address, 'utf-8');

    serialization.writeUInt8(id.length);
    serialization.writeString(id);

    serialization.writeUInt32LE(Math.floor(date.getTime() / 1_000));

    const ttlBuffer = Buffer.allocUnsafe(3);
    ttlBuffer.writeUIntLE(ttl, 0, 3);
    serialization.writeBuffer(ttlBuffer);

    serialization.writeUInt32LE(payloadBuffer.byteLength);
    serialization.writeBuffer(Buffer.from(payloadBuffer));

    const finalSignature = Buffer.from(
      signature ||
        (await cmsSignedData.sign(
          bufferToArray(serialization.toBuffer()),
          senderPrivateKey,
          senderCertificate,
        )),
    );
    serialization.writeUInt16LE(finalSignature.byteLength);
    serialization.writeBuffer(finalSignature);

    return bufferToArray(serialization.toBuffer());
  }
});

function parseMessage(messageSerialized: ArrayBuffer): MessageFields {
  return MESSAGE_PARSER.parse(Buffer.from(messageSerialized));
}

function parse24BitNumber(buffer: Buffer): number {
  return buffer.readUIntLE(0, 3);
}
