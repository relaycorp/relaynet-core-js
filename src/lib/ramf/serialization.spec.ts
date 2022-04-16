import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import * as jestDateMock from 'jest-date-mock';
import moment from 'moment';
import { SmartBuffer } from 'smart-buffer';

import {
  arrayBufferFrom,
  expectPkijsValuesToBeEqual,
  generateStubCert,
  getAsn1SequenceItem,
  getPromiseRejection,
} from '../_test_utils';
import { dateToASN1DateTimeInUTC, makeImplicitlyTaggedSequence } from '../asn1';
import { derDeserialize } from '../crypto_wrappers/_utils';
import * as cmsSignedData from '../crypto_wrappers/cms/signedData';
import { generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { StubMessage } from './_test_utils';
import RAMFSyntaxError from './RAMFSyntaxError';
import RAMFValidationError from './RAMFValidationError';
import { deserialize, serialize } from './serialization';

const PAYLOAD = Buffer.from('Hi');
const MAX_PAYLOAD_LENGTH = 2 ** 23 - 1;
const MAX_TTL = 15552000;

const NOW = new Date();
// There should be tests covering rounding when there are milliseconds
NOW.setMilliseconds(0);

const stubConcreteMessageTypeOctet = 0x44;
const stubConcreteMessageVersionOctet = 0x2;

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
  const RECIPIENT_ADDRESS = '0123456789';

  let SENDER_PRIVATE_KEY: CryptoKey;
  let SENDER_CERTIFICATE: Certificate;
  beforeAll(async () => {
    const yesterday = new Date(NOW);
    yesterday.setDate(yesterday.getDate() - 1);
    const tomorrow = new Date(NOW);
    tomorrow.setDate(tomorrow.getDate() + 1);
    const certificateAttributes = { validityStartDate: yesterday, validityEndDate: tomorrow };

    const senderKeyPair = await generateRSAKeyPair();
    SENDER_PRIVATE_KEY = senderKeyPair.privateKey;
    SENDER_CERTIFICATE = await generateStubCert({
      attributes: certificateAttributes,
      subjectPublicKey: senderKeyPair.publicKey,
    });
  });

  beforeEach(() => {
    jestDateMock.advanceTo(NOW);
  });

  describe('serialize', () => {
    describe('Format signature', () => {
      let stubMessage: StubMessage;
      beforeAll(() => {
        stubMessage = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
      });

      test('The ASCII string "Relaynet" should be at the start', async () => {
        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          SENDER_PRIVATE_KEY,
        );
        const formatSignature = parseFormatSignature(messageSerialized);
        expect(formatSignature).toHaveProperty('magic', 'Relaynet');
      });

      test('The concrete message type should be represented with an octet', async () => {
        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          SENDER_PRIVATE_KEY,
        );
        const formatSignature = parseFormatSignature(messageSerialized);
        expect(formatSignature).toHaveProperty('concreteMessageType', stubConcreteMessageTypeOctet);
      });

      test('The concrete message version should be at the end', async () => {
        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          SENDER_PRIVATE_KEY,
        );
        const formatSignature = parseFormatSignature(messageSerialized);
        expect(formatSignature).toHaveProperty(
          'concreteMessageVersion',
          stubConcreteMessageVersionOctet,
        );
      });
    });

    describe('SignedData', () => {
      let senderCaCertificateChain: readonly Certificate[];
      let cmsSignArgs: readonly any[];
      beforeAll(async () => {
        senderCaCertificateChain = [await generateStubCert()];
        const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
          senderCaCertificateChain,
        });

        jest.spyOn(cmsSignedData, 'sign');
        await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          SENDER_PRIVATE_KEY,
        );
        expect(cmsSignedData.sign).toBeCalledTimes(1);
        // @ts-ignore
        cmsSignArgs = cmsSignedData.sign.mock.calls[0];
      });

      test('The sender private key should be used to generate signature', () => {
        const actualSenderPrivateKey = cmsSignArgs[1];

        expect(actualSenderPrivateKey).toBe(SENDER_PRIVATE_KEY);
      });

      test('The sender certificate should be used to generate signature', () => {
        const actualSenderCertificate = cmsSignArgs[2];

        expect(actualSenderCertificate).toBe(SENDER_CERTIFICATE);
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
        async (hashingAlgorithmName) => {
          const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);

          jest.spyOn(cmsSignedData, 'sign');
          await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            SENDER_PRIVATE_KEY,
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

    describe('Fields', () => {
      test('Fields should be contained in SignedData value', async () => {
        const stubMessage = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);

        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          SENDER_PRIVATE_KEY,
        );

        await deserializeFields(messageSerialized);
      });

      test('Fields should be serialized as a 5-item ASN.1 sequence', async () => {
        const stubMessage = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);

        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          SENDER_PRIVATE_KEY,
        );
        const fields = await deserializeFields(messageSerialized);
        expect(fields).toBeInstanceOf(asn1js.Sequence);
        expect(fields.valueBlock.value).toHaveLength(5);
      });

      describe('Recipient address', () => {
        test('Address should be the first item', async () => {
          const stubMessage = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);

          const messageSerialized = await serialize(
            stubMessage,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            SENDER_PRIVATE_KEY,
          );
          const fields = await deserializeFields(messageSerialized);
          const addressDeserialized = getAsn1SequenceItem(fields, 0);
          expect(addressDeserialized.valueBlock.valueHex).toEqual(
            arrayBufferFrom(RECIPIENT_ADDRESS),
          );
        });

        test('Address should not span more than 1024 characters', async () => {
          const invalidAddress = 'a'.repeat(1025);
          const stubMessage = new StubMessage(invalidAddress, SENDER_CERTIFICATE, PAYLOAD);

          await expect(
            serialize(
              stubMessage,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              SENDER_PRIVATE_KEY,
            ),
          ).rejects.toEqual(
            new RAMFSyntaxError(
              'Recipient address should not span more than 1024 characters (got 1025)',
            ),
          );
        });
      });

      describe('Message id', () => {
        test('Id should be the second item', async () => {
          const idLength = 64;
          const id = 'a'.repeat(idLength);
          const stubMessage = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
            id,
          });

          const messageSerialized = await serialize(
            stubMessage,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            SENDER_PRIVATE_KEY,
          );
          const fields = await deserializeFields(messageSerialized);
          const idField = getAsn1SequenceItem(fields, 1);
          expect(idField.valueBlock.valueHex).toEqual(arrayBufferFrom(stubMessage.id));
        });

        test('Ids longer than 64 characters should be refused', async () => {
          const id = 'a'.repeat(65);
          const stubMessage = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
            id,
          });

          await expect(
            serialize(
              stubMessage,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              SENDER_PRIVATE_KEY,
            ),
          ).rejects.toEqual(
            new RAMFSyntaxError('Id should not span more than 64 characters (got 65)'),
          );
        });
      });

      describe('Date', () => {
        test('Date should be serialized with UTC and second-level precision', async () => {
          const nonUtcDate = new Date('01 Jan 2019 12:00:00 GMT+11:00');
          const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
            creationDate: nonUtcDate,
          });

          const messageSerialized = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            SENDER_PRIVATE_KEY,
          );

          const fields = await deserializeFields(messageSerialized);
          const datetimeBlock = getAsn1SequenceItem(fields, 2);
          expect(datetimeBlock.valueBlock.valueHex).toEqual(
            dateToASN1DateTimeInUTC(nonUtcDate).valueBlock.valueHex,
          );
        });
      });

      describe('TTL', () => {
        test('TTL should be serialized as an integer', async () => {
          const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);

          const messageSerialized = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            SENDER_PRIVATE_KEY,
          );
          const fields = await deserializeFields(messageSerialized);
          const ttlBlock = getAsn1SequenceItem(fields, 3);
          const ttlIntegerBlock = new asn1js.Integer({
            valueHex: ttlBlock.valueBlock.valueHex,
          } as any);
          expect(ttlIntegerBlock.valueBlock.valueDec).toEqual(message.ttl);
        });

        test('TTL of zero should be accepted', async () => {
          const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
            ttl: 0,
          });

          const messageSerialized = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            SENDER_PRIVATE_KEY,
          );

          const fields = await deserializeFields(messageSerialized);
          const ttlBlock = getAsn1SequenceItem(fields, 3);
          const ttlIntegerBlock = new asn1js.Integer({
            valueHex: ttlBlock.valueBlock.valueHex,
          } as any);
          expect(ttlIntegerBlock.valueBlock.valueDec).toEqual(0);
        });

        test('TTL should not be negative', async () => {
          const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
            ttl: -1,
          });
          await expect(
            serialize(
              message,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              SENDER_PRIVATE_KEY,
            ),
          ).rejects.toEqual(new RAMFSyntaxError('TTL cannot be negative'));
        });

        test('TTL should not be more than 180 days', async () => {
          const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
            ttl: MAX_TTL + 1,
          });
          await expect(
            serialize(
              message,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              SENDER_PRIVATE_KEY,
            ),
          ).rejects.toEqual(
            new RAMFSyntaxError(`TTL must be less than ${MAX_TTL} (got ${MAX_TTL + 1})`),
          );
        });
      });

      describe('Payload', () => {
        test('Payload should be serialized as an OCTET STRING', async () => {
          const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);

          const messageSerialized = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            SENDER_PRIVATE_KEY,
          );

          const fields = await deserializeFields(messageSerialized);
          const payloadBlock = getAsn1SequenceItem(fields, 4);
          expect(payloadBlock.valueBlock.valueHex).toEqual(bufferToArray(PAYLOAD));
        });

        test('Payload can span up to 8 MiB', async () => {
          const largePayload = Buffer.from('a'.repeat(MAX_PAYLOAD_LENGTH));
          const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, largePayload);

          const messageSerialized = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            SENDER_PRIVATE_KEY,
          );

          const fields = await deserializeFields(messageSerialized);
          const payloadBlock = getAsn1SequenceItem(fields, 4);
          expect(Buffer.from((payloadBlock as asn1js.OctetString).valueBlock.valueHex)).toEqual(
            largePayload,
          );
        });

        test('Payload size should not exceed 8 MiB', async () => {
          const largePayload = Buffer.from('a'.repeat(MAX_PAYLOAD_LENGTH + 1));
          const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, largePayload);
          await expect(
            serialize(
              message,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              SENDER_PRIVATE_KEY,
            ),
          ).rejects.toEqual(
            new RAMFSyntaxError(
              `Payload size must not exceed 8 MiB (got ${largePayload.byteLength} octets)`,
            ),
          );
        });
      });

      async function deserializeFields(messageSerialized: ArrayBuffer): Promise<asn1js.Sequence> {
        // Skip format signature
        const cmsSignedDataSerialized = messageSerialized.slice(10);
        const { plaintext } = await cmsSignedData.verifySignature(cmsSignedDataSerialized);
        return derDeserialize(plaintext) as asn1js.Sequence;
      }
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
      ).rejects.toThrowWithMessage(
        RAMFSyntaxError,
        'RAMF format signature does not begin with "Relaynet"',
      );
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
        const serialization = bufferToArray(Buffer.from('a'.repeat(9)));
        await expect(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        ).rejects.toThrowWithMessage(
          RAMFSyntaxError,
          'Serialization is too small to contain RAMF format signature',
        );
      });

      test('Input should be refused if it does not start with "Relaynet"', async () => {
        const serialization = bufferToArray(Buffer.from('Relaycorp00'));
        await expect(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        ).rejects.toThrowWithMessage(
          RAMFSyntaxError,
          'RAMF format signature does not begin with "Relaynet"',
        );
      });

      test('A non-matching concrete message type should be refused', async () => {
        const altMessage = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
        const serialization = await serialize(
          altMessage,
          stubConcreteMessageTypeOctet + 1,
          stubConcreteMessageVersionOctet,
          SENDER_PRIVATE_KEY,
        );

        await expect(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        ).rejects.toThrowWithMessage(
          RAMFSyntaxError,
          'Expected concrete message type 0x44 but got 0x45',
        );
      });

      test('A non-matching concrete message version should be refused', async () => {
        const altMessage = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
        const serialization = await serialize(
          altMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet + 1,
          SENDER_PRIVATE_KEY,
        );

        await expect(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        ).rejects.toThrowWithMessage(
          RAMFSyntaxError,
          'Expected concrete message version 0x2 but got 0x3',
        );
      });
    });

    describe('SignedData', () => {
      test('Signature should not be accepted if invalid', async () => {
        const differentSignerKeyPair = await generateRSAKeyPair();
        const differentSignerCertificate = await generateStubCert({
          issuerPrivateKey: differentSignerKeyPair.privateKey,
          subjectPublicKey: differentSignerKeyPair.publicKey,
        });

        const messageSerialized = await serializeRamfWithoutValidation(
          [],
          differentSignerCertificate,
        );

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
        const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
        const messageSerialized = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          SENDER_PRIVATE_KEY,
        );

        const messageDeserialized = await deserialize(
          messageSerialized,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        );

        expectPkijsValuesToBeEqual(
          messageDeserialized.senderCertificate.pkijsCertificate,
          SENDER_CERTIFICATE.pkijsCertificate,
        );
      });

      test('Sender certificate chain should be extracted from signature', async () => {
        const caCertificate = await generateStubCert();
        const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
          senderCaCertificateChain: [caCertificate],
        });
        const messageSerialized = await serialize(
          message,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          SENDER_PRIVATE_KEY,
        );

        const { senderCaCertificateChain } = await deserialize(
          messageSerialized,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          StubMessage,
        );

        expect(senderCaCertificateChain).toHaveLength(1);
        expect(senderCaCertificateChain[0].isEqual(caCertificate)).toBeTrue();
      });
    });

    describe('Fields', () => {
      test('Fields should be DER-encoded', async () => {
        const serializer = new SmartBuffer();
        serializer.writeString('Relaynet');
        serializer.writeUInt8(stubConcreteMessageTypeOctet);
        serializer.writeUInt8(stubConcreteMessageVersionOctet);
        serializer.writeBuffer(
          Buffer.from(
            await cmsSignedData.sign(
              bufferToArray(Buffer.from('Not a DER value')),
              SENDER_PRIVATE_KEY,
              SENDER_CERTIFICATE,
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
        ).rejects.toEqual(new RAMFSyntaxError('Invalid RAMF fields'));
      });

      test('Fields should be serialized as a sequence', async () => {
        const serializer = new SmartBuffer();
        serializer.writeString('Relaynet');
        serializer.writeUInt8(stubConcreteMessageTypeOctet);
        serializer.writeUInt8(stubConcreteMessageVersionOctet);

        const signedData = await cmsSignedData.SignedData.sign(
          new asn1js.Null().toBER(false),
          SENDER_PRIVATE_KEY,
          SENDER_CERTIFICATE,
        );
        serializer.writeBuffer(Buffer.from(signedData.serialize()));

        const serialization = serializer.toBuffer();

        await expect(
          deserialize(
            bufferToArray(serialization),
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        ).rejects.toEqual(new RAMFSyntaxError('Invalid RAMF fields'));
      });

      test('Fields sequence should not have fewer than 5 items', async () => {
        const serialization = await serializeRamfWithoutValidation([
          new asn1js.VisibleString({ value: 'address' }),
          new asn1js.VisibleString({ value: 'the-id' }),
          dateToASN1DateTimeInUTC(NOW),
          new asn1js.Integer({ value: 1_000 }),
        ]);

        await expect(
          deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        ).rejects.toEqual(new RAMFSyntaxError('Invalid RAMF fields'));
      });

      describe('Recipient address', () => {
        test('Address should be extracted', async () => {
          const address = 'a'.repeat(1024);
          const message = new StubMessage(address, SENDER_CERTIFICATE, PAYLOAD);
          const serialization = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            SENDER_PRIVATE_KEY,
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
          const messageSerialized = await serializeRamfWithoutValidation([
            new asn1js.VisibleString({ value: address }),
            new asn1js.VisibleString({ value: 'the-id' }),
            dateToASN1DateTimeInUTC(NOW),
            new asn1js.Integer({ value: 1_000 }),
            new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }),
          ]);
          await expect(
            deserialize(
              messageSerialized,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              StubMessage,
            ),
          ).rejects.toEqual(
            new RAMFSyntaxError(
              'Recipient address should not span more than 1024 characters (got 1025)',
            ),
          );
        });

        test('Private addresses should be accepted', async () => {
          const address = '0deadbeef';
          const message = new StubMessage(address, SENDER_CERTIFICATE, PAYLOAD);
          const serialization = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            SENDER_PRIVATE_KEY,
          );

          const deserialization = await deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          );
          expect(deserialization.recipientAddress).toEqual(address);
        });

        test('Public addresses should be accepted', async () => {
          const address = 'https://example.com';
          const message = new StubMessage(address, SENDER_CERTIFICATE, PAYLOAD);
          const serialization = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            SENDER_PRIVATE_KEY,
          );

          const deserialization = await deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          );
          expect(deserialization.recipientAddress).toEqual(address);
        });

        test('Invalid addresses should be refused', async () => {
          const invalidAddress = 'not valid';
          const message = new StubMessage(invalidAddress, SENDER_CERTIFICATE, PAYLOAD);
          const serialization = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            SENDER_PRIVATE_KEY,
          );

          await expect(
            deserialize(
              serialization,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              StubMessage,
            ),
          ).rejects.toEqual(
            new RAMFSyntaxError(
              `Recipient address should be a valid node address (got: "${invalidAddress}")`,
            ),
          );
        });
      });

      describe('Message id', () => {
        test('Id should be deserialized', async () => {
          const id = 'a'.repeat(64);
          const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, { id });
          const serialization = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            SENDER_PRIVATE_KEY,
          );
          const deserialization = await deserialize(
            serialization,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          );
          expect(deserialization.id).toEqual(id);
        });

        test('Id should not exceed 64 characters', async () => {
          const id = 'a'.repeat(65);
          const messageSerialized = await serializeRamfWithoutValidation([
            new asn1js.VisibleString({ value: RECIPIENT_ADDRESS }),
            new asn1js.VisibleString({ value: id }),
            dateToASN1DateTimeInUTC(NOW),
            new asn1js.Integer({ value: 1_000 }),
            new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }),
          ]);
          await expect(
            deserialize(
              messageSerialized,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              StubMessage,
            ),
          ).rejects.toEqual(
            new RAMFSyntaxError('Id should not span more than 64 characters (got 65)'),
          );
        });
      });

      describe('Date', () => {
        test('Valid date should be accepted', async () => {
          const date = moment.utc(NOW).format('YYYYMMDDHHmmss');
          const messageSerialized = await serializeRamfWithoutValidation([
            new asn1js.VisibleString({ value: RECIPIENT_ADDRESS }),
            new asn1js.VisibleString({ value: 'id' }),
            new asn1js.DateTime({ value: date }),
            new asn1js.Integer({ value: 1_000 }),
            new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }),
          ]);

          const message = await deserialize(
            messageSerialized,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          );

          expect(message.creationDate).toEqual(NOW);
        });

        test('Date not serialized as an ASN.1 DATE-TIME should be refused', async () => {
          const messageSerialized = await serializeRamfWithoutValidation([
            new asn1js.VisibleString({ value: 'the-address' }),
            new asn1js.VisibleString({ value: 'id' }),
            new asn1js.DateTime({ value: '42' }),
            new asn1js.Integer({ value: 1_000 }),
            new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }),
          ]);

          await expect(
            deserialize(
              messageSerialized,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              StubMessage,
            ),
          ).rejects.toMatchObject({
            message: /^Message date is invalid:/,
          });
        });
      });

      describe('TTL', () => {
        test('TTL of exactly 180 days should be accepted', async () => {
          const messageSerialized = await serializeRamfWithoutValidation([
            new asn1js.VisibleString({ value: RECIPIENT_ADDRESS }),
            new asn1js.VisibleString({ value: 'the-id' }),
            dateToASN1DateTimeInUTC(NOW),
            new asn1js.Integer({ value: MAX_TTL }),
            new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }),
          ]);

          await expect(
            deserialize(
              messageSerialized,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              StubMessage,
            ),
          ).resolves.toHaveProperty('ttl', MAX_TTL);
        });

        test('TTL greater than 180 days should not be accepted', async () => {
          const messageSerialized = await serializeRamfWithoutValidation([
            new asn1js.VisibleString({ value: RECIPIENT_ADDRESS }),
            new asn1js.VisibleString({ value: 'the-id' }),
            dateToASN1DateTimeInUTC(NOW),
            new asn1js.Integer({ value: MAX_TTL + 1 }),
            new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }),
          ]);
          await expect(
            deserialize(
              messageSerialized,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              StubMessage,
            ),
          ).rejects.toEqual(
            new RAMFSyntaxError(`TTL must be less than ${MAX_TTL} (got ${MAX_TTL + 1})`),
          );
        });
      });

      describe('Payload', () => {
        test('Payload should be extracted', async () => {
          const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
          const messageSerialized = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            SENDER_PRIVATE_KEY,
          );

          const messageDeserialized = await deserialize(
            messageSerialized,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          );

          expect(messageDeserialized.payloadSerialized).toEqual(PAYLOAD);
        });

        test('Payload size should not exceed 8 MiB', async () => {
          const largePayload = Buffer.from('a'.repeat(MAX_PAYLOAD_LENGTH + 1));
          const messageSerialized = await serializeRamfWithoutValidation([
            new asn1js.VisibleString({ value: RECIPIENT_ADDRESS }),
            new asn1js.VisibleString({ value: 'the-id' }),
            dateToASN1DateTimeInUTC(NOW),
            new asn1js.Integer({ value: 1_000 }),
            new asn1js.OctetString({ valueHex: bufferToArray(largePayload) }),
          ]);

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
    });

    test('Valid messages should be successfully deserialized', async () => {
      const message = new StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
      const messageSerialized = await serialize(
        message,
        stubConcreteMessageTypeOctet,
        stubConcreteMessageVersionOctet,
        SENDER_PRIVATE_KEY,
      );

      jest.spyOn(cmsSignedData, 'verifySignature');
      const messageDeserialized = await deserialize(
        messageSerialized,
        stubConcreteMessageTypeOctet,
        stubConcreteMessageVersionOctet,
        StubMessage,
      );

      expect(messageDeserialized.recipientAddress).toEqual(message.recipientAddress);
      expect(messageDeserialized.senderCertificate.isEqual(message.senderCertificate)).toBeTrue();
      expect(messageDeserialized.payloadSerialized).toEqual(message.payloadSerialized);
    });

    async function serializeRamfWithoutValidation(
      sequenceItems: ReadonlyArray<asn1js.BaseBlock<any>>,
      senderCertificate?: Certificate,
    ): Promise<ArrayBuffer> {
      const serializer = new SmartBuffer();
      serializer.writeString('Relaynet');
      serializer.writeUInt8(stubConcreteMessageTypeOctet);
      serializer.writeUInt8(stubConcreteMessageVersionOctet);

      const signedData = await cmsSignedData.SignedData.sign(
        makeImplicitlyTaggedSequence(...sequenceItems).toBER(),
        SENDER_PRIVATE_KEY,
        senderCertificate ?? SENDER_CERTIFICATE,
      );
      serializer.writeBuffer(Buffer.from(signedData.serialize()));

      return bufferToArray(serializer.toBuffer());
    }
  });
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
