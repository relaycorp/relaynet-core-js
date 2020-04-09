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
import { deserialize, MessageFieldSet, serialize } from './serialization';

const PAYLOAD = Buffer.from('Hi');
const MAX_PAYLOAD_LENGTH = 2 ** 23 - 1;

const STUB_DATE = new Date(2014, 1, 19);
STUB_DATE.setMilliseconds(0); // There should be tests covering rounding when there are milliseconds

const stubConcreteMessageTypeOctet = 0x44;
const stubConcreteMessageVersionOctet = 0x2;

const MESSAGE_FIELD_PARSER = new Parser()
  .endianess('little')
  .uint16('recipientAddressLength')
  .string('recipientAddress', { length: 'recipientAddressLength' })
  .uint8('idLength')
  .string('id', { length: 'idLength', encoding: 'ascii' })
  .uint32('dateTimestamp')
  .buffer('ttlBuffer', { length: 3 })
  // @ts-ignore
  .buffer('payloadLength', { length: 3, formatter: parse24BitNumber })
  .buffer('payload', { length: 'payloadLength' });

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
        const formatSignature = parseFormatSignature(messageSerialized);
        expect(formatSignature).toHaveProperty('magic', 'Relaynet');
      });

      test('The concrete message type should be represented with an octet', async () => {
        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const formatSignature = parseFormatSignature(messageSerialized);
        expect(formatSignature).toHaveProperty('concreteMessageType', stubConcreteMessageTypeOctet);
      });

      test('The concrete message version should be at the end', async () => {
        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const formatSignature = parseFormatSignature(messageSerialized);
        expect(formatSignature).toHaveProperty(
          'concreteMessageVersion',
          stubConcreteMessageVersionOctet,
        );
      });
    });

    describe('Fields', () => {
      test('Fields should be contained in SignedData value', async () => {
        const stubMessage = new StubMessage(recipientAddress, senderCertificate, PAYLOAD);
        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        // Skip format signature and check the remainder is just the CMS SignedData value
        const cmsSignedDataSerialized = messageSerialized.slice(10);
        await cmsSignedData.verifySignature(cmsSignedDataSerialized);
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
          const messageFields = await parseMessageFields(messageSerialized);
          expect(messageFields).toHaveProperty('recipientAddress', recipientAddress);
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
          const messageParts = await parseMessageFields(messageSerialized);
          expect(messageParts).toHaveProperty('recipientAddress', address);
        });

        test('Address should not span more than 1024 octets', async () => {
          const invalidAddress = 'a'.repeat(1025);
          const stubMessage = new StubMessage(invalidAddress, senderCertificate, PAYLOAD);

          await expectPromiseToReject(
            serialize(
              stubMessage,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              senderPrivateKey,
            ),
            new RAMFSyntaxError(
              'Recipient address should not span more than 1024 octets (got 1025)',
            ),
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
          const messageParts = await parseMessageFields(messageSerialized);
          expect(messageParts).toHaveProperty('recipientAddress', NON_ASCII_STRING);
        });

        test('Multi-byte characters should be accounted for in length validation', async () => {
          const invalidAddress =
            NON_ASCII_STRING + 'a'.repeat(1025 - Buffer.byteLength(NON_ASCII_STRING));
          expect(Buffer.byteLength(invalidAddress)).toEqual(1025);
          const stubMessage = new StubMessage(invalidAddress, senderCertificate, PAYLOAD);

          await expectPromiseToReject(
            serialize(
              stubMessage,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              senderPrivateKey,
            ),
            new RAMFSyntaxError(
              'Recipient address should not span more than 1024 octets (got 1025)',
            ),
          );
        });
      });

      describe('Message id', () => {
        test('Id should be up to 64 characters long', async () => {
          const idLength = 64;
          const id = 'a'.repeat(idLength);
          const stubMessage = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, { id });

          const messageSerialized = await serialize(
            stubMessage,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          );
          const messageParts = await parseMessageFields(messageSerialized);
          expect(messageParts).toHaveProperty('idLength', idLength);
          expect(messageParts).toHaveProperty('id', stubMessage.id);
        });

        test('Ids longer than 64 characters should be refused', async () => {
          const id = 'a'.repeat(65);
          const stubMessage = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, { id });

          await expectPromiseToReject(
            serialize(
              stubMessage,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              senderPrivateKey,
            ),
            new RAMFSyntaxError('Id should not span more than 64 characters (got 65)'),
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
          const messageParts = await parseMessageFields(messageSerialized);
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
          const messageParts = await parseMessageFields(messageSerialized);
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

          const messageParts = await parseMessageFields(messageSerialized);
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
          const messageParts = await parseMessageFields(messageSerialized);
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

          const messageParts = await parseMessageFields(messageSerialized);
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

      describe('Payload', () => {
        test('Payload can span up to 8 MiB', async () => {
          // This test is painfully slow: https://github.com/relaycorp/relaynet-core-js/issues/57
          jest.setTimeout(7000);

          const largePayload = Buffer.from('a'.repeat(MAX_PAYLOAD_LENGTH));
          const message = new StubMessage(recipientAddress, senderCertificate, largePayload);

          const messageSerialized = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          );

          const messageParts = await parseMessageFields(messageSerialized);
          expectBuffersToEqual(messageParts.payload, largePayload);
        });

        test('Payload size should not exceed 8 MiB', async () => {
          const largePayload = Buffer.from('a'.repeat(MAX_PAYLOAD_LENGTH + 1));
          const message = new StubMessage(recipientAddress, senderCertificate, largePayload);
          await expectPromiseToReject(
            serialize(
              message,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              senderPrivateKey,
            ),
            new RAMFSyntaxError(
              `Payload size must not exceed 8 MiB (got ${largePayload.byteLength} octets)`,
            ),
          );
        });
      });

      describe('Signature', () => {
        let senderCaCertificateChain: readonly Certificate[];
        let cmsSignArgs: readonly any[];
        beforeAll(async () => {
          senderCaCertificateChain = [await generateStubCert()];
          const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
            senderCaCertificateChain,
          });

          jest.spyOn(cmsSignedData, 'sign');
          await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          );
          expect(cmsSignedData.sign).toBeCalledTimes(1);
          // @ts-ignore
          cmsSignArgs = cmsSignedData.sign.mock.calls[0];
        });

        test('The sender private key should be used to generate signature', () => {
          const actualSenderPrivateKey = cmsSignArgs[1];

          expect(actualSenderPrivateKey).toBe(senderPrivateKey);
        });

        test('The sender certificate should be used to generate signature', () => {
          const actualSenderCertificate = cmsSignArgs[2];

          expect(actualSenderCertificate).toBe(senderCertificate);
        });

        test('Sender certificate chain should be attached', () => {
          const attachedCertificates = cmsSignArgs[3];

          expect(attachedCertificates).toHaveLength(senderCaCertificateChain.length);
          for (const cert of senderCaCertificateChain) {
            expect(attachedCertificates).toContain(cert);
          }
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
  });

  describe('deserialize', () => {
    const octetsIn9Mib = 9437184;

    test('Messages up to 9 MiB should be accepted', async () => {
      const serialization = bufferToArray(Buffer.from('a'.repeat(octetsIn9Mib)));

      // Deserialization still fails, but for a different reason
      await expect(
        deserialize(
          serialization,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        ),
      ).rejects.toMatchObject<Partial<RAMFSyntaxError>>({
        message: expect.stringMatching(/^Serialization starts with invalid RAMF format signature/),
      });
    });

    test('Messages larger than 9 MiB should be refused', async () => {
      const serializationLength = octetsIn9Mib + 1;
      const serialization = bufferToArray(Buffer.from('a'.repeat(serializationLength)));

      await expect(
        deserialize(
          serialization,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        ),
      ).rejects.toMatchObject<Partial<RAMFSyntaxError>>({
        message: `Message should not be longer than 9 MiB (got ${serializationLength} octets)`,
      });
    });

    describe('Format signature', () => {
      test('Input should be long enough to contain format signature', async () => {
        const serialization = bufferToArray(Buffer.from('Relay'));
        await expectPromiseToReject(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
          new RAMFSyntaxError(
            'Serialization starts with invalid RAMF format signature: Relaynet is not defined',
          ),
        );
      });

      test('Input should be refused if it does not start with "Relaynet"', async () => {
        const serialization = bufferToArray(Buffer.from('Relaycorp00'));
        await expectPromiseToReject(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
          new RAMFSyntaxError(
            'Serialization starts with invalid RAMF format signature: Relaynet is not defined',
          ),
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

      test('Address should not span more than 1024 octets', async () => {
        const address = 'a'.repeat(1025);
        const messageSerialized = await serializeWithoutValidation({ address });
        await expectPromiseToReject(
          deserialize(
            messageSerialized,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
          new RAMFSyntaxError('Recipient address should not span more than 1024 octets (got 1025)'),
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
        await expect(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        ).rejects.toMatchObject<Partial<RAMFValidationError>>({
          message: 'Message date is in the future',
        });
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
        await expect(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        ).rejects.toMatchObject<Partial<RAMFValidationError>>({
          message: 'Message was created before the sender certificate was valid',
        });
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
        await expect(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        ).rejects.toMatchObject<Partial<RAMFValidationError>>({
          message: 'Message was created after the sender certificate expired',
        });
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
        await expect(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        ).rejects.toMatchObject<Partial<RAMFValidationError>>({
          message: 'Message already expired',
        });
      });
    });

    describe('Payload', () => {
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

      test.skip('Payload size should not exceed 2 ** 23 octets', async () => {
        const largePayload = Buffer.from('a'.repeat(MAX_PAYLOAD_LENGTH + 1));
        const messageSerialized = await serializeWithoutValidation({ payloadBuffer: largePayload });

        await expect(
          deserialize(
            messageSerialized,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        ).rejects.toMatchObject<Partial<RAMFValidationError>>({
          message: `Payload size must not exceed 8 MiB (got ${largePayload.byteLength} octets)`,
        });
      });
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
        expect(cmsSignedData.verifySignature).toBeCalledTimes(1);
        expect(cmsSignedData.verifySignature).toBeCalledWith(signatureCiphertext);
      });

      test('Signature should not be accepted if invalid', async () => {
        const differentSignerKeyPair = await generateRSAKeyPair();
        const differentSignerCertificate = await generateStubCert({
          issuerPrivateKey: differentSignerKeyPair.privateKey,
          subjectPublicKey: differentSignerKeyPair.publicKey,
        });

        const messageSerialized = await serializeWithoutValidation({}, differentSignerCertificate);

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
          'Invalid RAMF message signature: Invalid signature:  (PKI.js code: 14)',
        );
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
        const message = new StubMessage(recipientAddress, senderCertificate, PAYLOAD, {
          senderCaCertificateChain: [caCertificate],
        });
        const messageSerialized = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        const { senderCaCertificateChain } = await deserialize(
          messageSerialized,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        );

        expect(senderCaCertificateChain).toHaveLength(2);
        expect(senderCaCertificateChain[0].isEqual(senderCertificate)).toBeTrue();
        expect(senderCaCertificateChain[1].isEqual(caCertificate)).toBeTrue();
      });

      test('CMS SignedData content should contain fields', async () => {
        const serializer = new SmartBuffer();
        serializer.writeString('Relaynet');
        serializer.writeUInt8(stubConcreteMessageTypeOctet);
        serializer.writeUInt8(stubConcreteMessageVersionOctet);
        serializer.writeBuffer(
          Buffer.from(
            await cmsSignedData.sign(
              bufferToArray(Buffer.from('Not a valid field set')),
              senderPrivateKey,
              senderCertificate,
            ),
          ),
        );
        const serialization = serializer.toBuffer();

        await expect(
          deserialize(
            bufferToArray(serialization),
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        ).rejects.toMatchObject<Partial<RAMFSyntaxError>>({
          message: expect.stringMatching(/^CMS SignedData value contains invalid field set: /),
        });
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
    customSignerCertificate?: Certificate,
  ): Promise<ArrayBuffer> {
    const formatSignature = Buffer.allocUnsafe(10);
    formatSignature.write('Relaynet');
    formatSignature.writeUInt8(messageType, 8);
    formatSignature.writeUInt8(messageVersion, 9);

    const serialization = new SmartBuffer();

    serialization.writeUInt16LE(Buffer.byteLength(address));
    serialization.writeString(address, 'utf-8');

    serialization.writeUInt8(id.length);
    serialization.writeString(id);

    serialization.writeUInt32LE(Math.floor(date.getTime() / 1_000));

    const ttlBuffer = Buffer.allocUnsafe(3);
    ttlBuffer.writeUIntLE(ttl, 0, 3);
    serialization.writeBuffer(ttlBuffer);

    const payloadLength = Buffer.allocUnsafe(3);
    payloadLength.writeUIntLE(payloadBuffer.byteLength, 0, 3);
    serialization.writeBuffer(payloadLength);
    serialization.writeBuffer(payloadBuffer);

    const cmsSignedDataSerialized = await cmsSignedData.sign(
      bufferToArray(serialization.toBuffer()),
      senderPrivateKey,
      customSignerCertificate ?? senderCertificate,
    );
    const messageSerialized = Buffer.concat([
      formatSignature,
      new Uint8Array(cmsSignedDataSerialized),
    ]);
    return bufferToArray(messageSerialized);
  }
});

interface MessageFormatSignature {
  readonly magic: string;
  readonly concreteMessageType: number;
  readonly concreteMessageVersion: number;
}

function parseFormatSignature(messageSerialized: ArrayBuffer): MessageFormatSignature {
  const buffer = Buffer.from(messageSerialized);
  return {
    concreteMessageType: buffer.readUInt8(8),
    concreteMessageVersion: buffer.readUInt8(9),
    magic: buffer.slice(0, 8).toString(),
  };
}

async function parseMessageFields(messageSerialized: ArrayBuffer): Promise<MessageFieldSet> {
  const buffer = Buffer.from(messageSerialized);
  const cmsSignedDataSerialized = bufferToArray(buffer.slice(10));
  const { plaintext } = await cmsSignedData.verifySignature(cmsSignedDataSerialized);
  return MESSAGE_FIELD_PARSER.parse(Buffer.from(plaintext));
}

function parse24BitNumber(buffer: Buffer): number {
  return buffer.readUIntLE(0, 3);
}
