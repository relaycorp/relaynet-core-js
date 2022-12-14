import {
  BaseBlock,
  Constructed,
  DateTime,
  Integer,
  Null,
  OctetString,
  Sequence,
  VisibleString,
} from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import { addDays, setMilliseconds, subDays } from 'date-fns';
import * as jestDateMock from 'jest-date-mock';
import moment from 'moment';
import { SmartBuffer } from 'smart-buffer';

import {
  arrayBufferFrom,
  expectPkijsValuesToBeEqual,
  generateStubCert,
  getConstructedItemFromConstructed,
  getPrimitiveItemFromConstructed,
} from '../_test_utils';
import { dateToASN1DateTimeInUTC, makeImplicitlyTaggedSequence } from '../asn1';
import { derDeserialize } from '../crypto_wrappers/_utils';
import { HashingAlgorithm } from '../crypto_wrappers/algorithms';
import * as cmsSignedData from '../crypto_wrappers/cms/signedData';
import { generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { Recipient } from '../messages/Recipient';
import { StubMessage } from './_test_utils';
import RAMFSyntaxError from './RAMFSyntaxError';
import RAMFValidationError from './RAMFValidationError';
import { deserialize, serialize } from './serialization';

const PAYLOAD = Buffer.from('Hi');
const MAX_PAYLOAD_LENGTH = 2 ** 23 - 1;
const MAX_TTL = 15552000;

// There should be tests covering rounding when there are milliseconds
const NOW = setMilliseconds(new Date(), 0);

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
  const RECIPIENT_ID = '0123456789';
  const RECIPIENT: Recipient = { id: RECIPIENT_ID };
  const INTERNET_ADDRESS = 'example.com';

  let senderPrivateKey: CryptoKey;
  let senderCertificate: Certificate;
  beforeAll(async () => {
    const senderKeyPair = await generateRSAKeyPair();
    senderPrivateKey = senderKeyPair.privateKey;
    senderCertificate = await generateStubCert({
      attributes: {
        validityStartDate: subDays(NOW, 1),
        validityEndDate: addDays(NOW, 1),
      },
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
        stubMessage = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);
      });

      test('The ASCII string "Awala" should be at the start', async () => {
        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const formatSignature = parseFormatSignature(messageSerialized);
        expect(formatSignature).toHaveProperty('magic', 'Awala');
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

    describe('SignedData', () => {
      let senderCaCertificateChain: readonly Certificate[];
      let cmsSignArgs: readonly any[];
      beforeAll(async () => {
        senderCaCertificateChain = [await generateStubCert()];
        const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD, {
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

      test.each(['SHA-384', 'SHA-512'] as readonly HashingAlgorithm[])(
        '%s should also be supported',
        async (hashingAlgorithmName) => {
          const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);

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

    describe('Fields', () => {
      test('Fields should be contained in SignedData value', async () => {
        const stubMessage = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);

        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );

        await deserializeFields(messageSerialized);
      });

      test('Fields should be serialized as a 5-item ASN.1 sequence', async () => {
        const stubMessage = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);

        const messageSerialized = await serialize(
          stubMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
        );
        const fields = await deserializeFields(messageSerialized);
        expect(fields).toBeInstanceOf(Sequence);
        expect(fields.valueBlock.value).toHaveLength(5);
      });

      describe('Recipient', () => {
        test('Recipient should be CONSTRUCTED', async () => {
          const stubMessage = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);

          const messageSerialized = await serialize(
            stubMessage,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          );

          const fields = await deserializeFields(messageSerialized);
          const recipientASN1 = getConstructedItemFromConstructed(fields, 0);
          expect(recipientASN1).toBeInstanceOf(Constructed);
        });

        describe('Id', () => {
          test('Id should be first item in sub-sequence', async () => {
            const stubMessage = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);

            const messageSerialized = await serialize(
              stubMessage,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              senderPrivateKey,
            );

            const fields = await deserializeFields(messageSerialized);
            const recipientASN1 = getConstructedItemFromConstructed(fields, 0);
            const idASN1 = getPrimitiveItemFromConstructed(recipientASN1, 0);
            expect(Buffer.from(idASN1.valueBlock.valueHexView)).toEqual(Buffer.from(RECIPIENT_ID));
          });

          test('Id should not span more than 1024 characters', async () => {
            const invalidId = 'a'.repeat(1025);
            const stubMessage = new StubMessage({ id: invalidId }, senderCertificate, PAYLOAD);

            await expect(
              serialize(
                stubMessage,
                stubConcreteMessageTypeOctet,
                stubConcreteMessageVersionOctet,
                senderPrivateKey,
              ),
            ).rejects.toEqual(
              new RAMFSyntaxError(
                'Recipient id should not span more than 1024 characters (got 1025)',
              ),
            );
          });
        });

        describe('Internet address', () => {
          test('Internet address should be absent if unspecified', async () => {
            expect(RECIPIENT.internetAddress).toBeUndefined();
            const stubMessage = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);

            const messageSerialized = await serialize(
              stubMessage,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              senderPrivateKey,
            );

            const fields = await deserializeFields(messageSerialized);
            const recipientASN1 = getConstructedItemFromConstructed(fields, 0);
            expect(recipientASN1.valueBlock.value.length).toEqual(1);
          });

          test('Internet address should be second item in sub-sequence', async () => {
            const stubMessage = new StubMessage(
              { ...RECIPIENT, internetAddress: INTERNET_ADDRESS },
              senderCertificate,
              PAYLOAD,
            );

            const messageSerialized = await serialize(
              stubMessage,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              senderPrivateKey,
            );

            const fields = await deserializeFields(messageSerialized);
            const recipientASN1 = getConstructedItemFromConstructed(fields, 0);
            const idASN1 = getPrimitiveItemFromConstructed(recipientASN1, 1);
            expect(Buffer.from(idASN1.valueBlock.valueHexView)).toEqual(
              Buffer.from(INTERNET_ADDRESS),
            );
          });

          test('Internet address should not span more than 1024 characters', async () => {
            const invalidInternetAddress = 'a'.repeat(1025);
            const stubMessage = new StubMessage(
              { ...RECIPIENT, internetAddress: invalidInternetAddress },
              senderCertificate,
              PAYLOAD,
            );

            await expect(
              serialize(
                stubMessage,
                stubConcreteMessageTypeOctet,
                stubConcreteMessageVersionOctet,
                senderPrivateKey,
              ),
            ).rejects.toEqual(
              new RAMFSyntaxError(
                'Recipient Internet address should not span more than 1024 characters (got 1025)',
              ),
            );
          });
        });
      });

      describe('Message id', () => {
        test('Id should be the second item', async () => {
          const idLength = 64;
          const id = 'a'.repeat(idLength);
          const stubMessage = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD, {
            id,
          });

          const messageSerialized = await serialize(
            stubMessage,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          );
          const fields = await deserializeFields(messageSerialized);
          const idField = getPrimitiveItemFromConstructed(fields, 1);
          expect(idField.valueBlock.valueHex).toEqual(arrayBufferFrom(stubMessage.id));
        });

        test('Ids longer than 64 characters should be refused', async () => {
          const id = 'a'.repeat(65);
          const stubMessage = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD, {
            id,
          });

          await expect(
            serialize(
              stubMessage,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              senderPrivateKey,
            ),
          ).rejects.toEqual(
            new RAMFSyntaxError('Id should not span more than 64 characters (got 65)'),
          );
        });
      });

      describe('Date', () => {
        test('Date should be serialized with UTC and second-level precision', async () => {
          const nonUtcDate = new Date('01 Jan 2019 12:00:00 GMT+11:00');
          const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD, {
            creationDate: nonUtcDate,
          });

          const messageSerialized = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          );

          const fields = await deserializeFields(messageSerialized);
          const datetimeBlock = getPrimitiveItemFromConstructed(fields, 2);
          expect(datetimeBlock.valueBlock.valueHex).toEqual(
            dateToASN1DateTimeInUTC(nonUtcDate).valueBlock.valueHex,
          );
        });
      });

      describe('TTL', () => {
        test('TTL should be serialized as an integer', async () => {
          const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);

          const messageSerialized = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          );
          const fields = await deserializeFields(messageSerialized);
          const ttlBlock = getPrimitiveItemFromConstructed(fields, 3);
          const ttlIntegerBlock = new Integer({
            valueHex: ttlBlock.valueBlock.valueHexView,
          });
          expect(Number(ttlIntegerBlock.toBigInt())).toEqual(message.ttl);
        });

        test('TTL of zero should be accepted', async () => {
          const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD, {
            ttl: 0,
          });

          const messageSerialized = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          );

          const fields = await deserializeFields(messageSerialized);
          const ttlBlock = getPrimitiveItemFromConstructed(fields, 3);
          const ttlIntegerBlock = new Integer({
            valueHex: ttlBlock.valueBlock.valueHex,
          } as any);
          expect(ttlIntegerBlock.valueBlock.valueDec).toEqual(0);
        });

        test('TTL should not be negative', async () => {
          const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD, {
            ttl: -1,
          });
          await expect(
            serialize(
              message,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              senderPrivateKey,
            ),
          ).rejects.toEqual(new RAMFSyntaxError('TTL cannot be negative'));
        });

        test('TTL should not be more than 180 days', async () => {
          const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD, {
            ttl: MAX_TTL + 1,
          });
          await expect(
            serialize(
              message,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              senderPrivateKey,
            ),
          ).rejects.toEqual(
            new RAMFSyntaxError(`TTL must be less than ${MAX_TTL} (got ${MAX_TTL + 1})`),
          );
        });
      });

      describe('Payload', () => {
        test('Payload should be serialized as an OCTET STRING', async () => {
          const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);

          const messageSerialized = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          );

          const fields = await deserializeFields(messageSerialized);
          const payloadBlock = getPrimitiveItemFromConstructed(fields, 4);
          expect(Buffer.from(payloadBlock.valueBlock.valueHex)).toEqual(PAYLOAD);
        });

        test('Payload can span up to 8 MiB', async () => {
          const largePayload = Buffer.from('a'.repeat(MAX_PAYLOAD_LENGTH));
          const message = new StubMessage(RECIPIENT, senderCertificate, largePayload);

          const messageSerialized = await serialize(
            message,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            senderPrivateKey,
          );

          const fields = await deserializeFields(messageSerialized);
          const payloadBlock = getPrimitiveItemFromConstructed(fields, 4);
          expect(Buffer.from((payloadBlock as OctetString).valueBlock.valueHex)).toEqual(
            largePayload,
          );
        });

        test('Payload size should not exceed 8 MiB', async () => {
          const largePayload = Buffer.from('a'.repeat(MAX_PAYLOAD_LENGTH + 1));
          const message = new StubMessage(RECIPIENT, senderCertificate, largePayload);
          await expect(
            serialize(
              message,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              senderPrivateKey,
            ),
          ).rejects.toEqual(
            new RAMFSyntaxError(
              `Payload size must not exceed 8 MiB (got ${largePayload.byteLength} octets)`,
            ),
          );
        });
      });

      async function deserializeFields(messageSerialized: ArrayBuffer): Promise<Sequence> {
        // Skip format signature
        const cmsSignedDataSerialized = messageSerialized.slice(7);
        const { plaintext } = await cmsSignedData.verifySignature(cmsSignedDataSerialized);
        return derDeserialize(plaintext) as Sequence;
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
        'RAMF format signature does not begin with "Awala"',
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
        const serialization = bufferToArray(Buffer.from('a'.repeat(6)));
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

      test('Input should be refused if it does not start with "Awala"', async () => {
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
          'RAMF format signature does not begin with "Awala"',
        );
      });

      test('A non-matching concrete message type should be refused', async () => {
        const altMessage = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);
        const serialization = await serialize(
          altMessage,
          stubConcreteMessageTypeOctet + 1,
          stubConcreteMessageVersionOctet,
          senderPrivateKey,
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
        const altMessage = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);
        const serialization = await serialize(
          altMessage,
          stubConcreteMessageTypeOctet,
          stubConcreteMessageVersionOctet + 1,
          senderPrivateKey,
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

        await expect(
          deserialize(
            messageSerialized,
            stubConcreteMessageTypeOctet,
            stubConcreteMessageVersionOctet,
            StubMessage,
          ),
        ).rejects.toThrowWithMessage(
          RAMFValidationError,
          /^Invalid RAMF message signature: Invalid signature/,
        );
      });

      test('Sender certificate should be extracted from signature', async () => {
        const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);
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
        const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD, {
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

        expect(senderCaCertificateChain).toHaveLength(1);
        expect(senderCaCertificateChain[0].isEqual(caCertificate)).toBeTrue();
      });
    });

    describe('Fields', () => {
      test('Fields should be DER-encoded', async () => {
        const serializer = new SmartBuffer();
        serializer.writeString('Awala');
        serializer.writeUInt8(stubConcreteMessageTypeOctet);
        serializer.writeUInt8(stubConcreteMessageVersionOctet);
        serializer.writeBuffer(
          Buffer.from(
            await cmsSignedData.sign(
              bufferToArray(Buffer.from('Not a DER value')),
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
        ).rejects.toEqual(new RAMFSyntaxError('Invalid RAMF fields'));
      });

      test('Fields should be serialized as a sequence', async () => {
        const serializer = new SmartBuffer();
        serializer.writeString('Awala');
        serializer.writeUInt8(stubConcreteMessageTypeOctet);
        serializer.writeUInt8(stubConcreteMessageVersionOctet);

        const signedData = await cmsSignedData.SignedData.sign(
          new Null().toBER(false),
          senderPrivateKey,
          senderCertificate,
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
          new VisibleString({ value: 'address' }),
          new VisibleString({ value: 'the-id' }),
          dateToASN1DateTimeInUTC(NOW),
          new Integer({ value: 1_000 }),
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

      describe('Recipient', () => {
        test('Recipient should be CONSTRUCTED', async () => {
          const serialization = await serializeRamfWithoutValidation([
            new VisibleString({ value: 'address' }),
            new VisibleString({ value: 'the-id' }),
            dateToASN1DateTimeInUTC(NOW),
            new Integer({ value: 1_000 }),
            new OctetString({ valueHex: arrayBufferFrom('payload') }),
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

        test('Recipient CONSTRUCTED value should contain at least 1 value', async () => {
          const serialization = await serializeRamfWithoutValidation([
            new Sequence({ value: [] }),
            new VisibleString({ value: 'the-id' }),
            dateToASN1DateTimeInUTC(NOW),
            new Integer({ value: 1_000 }),
            new OctetString({ valueHex: arrayBufferFrom('payload') }),
          ]);

          await expect(
            deserialize(
              serialization,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              StubMessage,
            ),
          ).rejects.toEqual(
            new RAMFSyntaxError('Recipient SEQUENCE should at least contain the id'),
          );
        });

        describe('Id', () => {
          test('Id should be extracted', async () => {
            const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);
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
            expect(deserialization.recipient.id).toEqual(RECIPIENT.id);
          });

          test('Id of up to 1024 octets should be accepted', async () => {
            const id = 'a'.repeat(1024);
            const message = new StubMessage({ id }, senderCertificate, PAYLOAD);
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
            expect(deserialization.recipient.id).toEqual(id);
          });

          test('Id spanning more than 1024 octets should be refused', async () => {
            const address = 'a'.repeat(1025);
            const messageSerialized = await serializeRamfWithoutValidation([
              new Sequence({ value: [new VisibleString({ value: address })] }),
              new VisibleString({ value: 'the-id' }),
              dateToASN1DateTimeInUTC(NOW),
              new Integer({ value: 1_000 }),
              new OctetString({ valueHex: new ArrayBuffer(0) }),
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
                'Recipient id should not span more than 1024 characters (got 1025)',
              ),
            );
          });

          test('Malformed id should be refused', async () => {
            const malformedId = 'not valid';
            const message = new StubMessage({ id: malformedId }, senderCertificate, PAYLOAD);
            const serialization = await serialize(
              message,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              senderPrivateKey,
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
              `Recipient id is malformed ("${malformedId}")`,
            );
          });
        });

        describe('Internet address', () => {
          test('Address should be undefined if absent', async () => {
            const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);
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
            expect(deserialization.recipient.internetAddress).toBeUndefined();
          });

          test('Domain name should be accepted', async () => {
            const message = new StubMessage(
              { ...RECIPIENT, internetAddress: INTERNET_ADDRESS },
              senderCertificate,
              PAYLOAD,
            );
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
            expect(deserialization.recipient.internetAddress).toEqual(INTERNET_ADDRESS);
          });

          test('Malformed domain name should be refused', async () => {
            const malformedDomainName = 'not valid';
            const message = new StubMessage(
              { ...RECIPIENT, internetAddress: malformedDomainName },
              senderCertificate,
              PAYLOAD,
            );
            const serialization = await serialize(
              message,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              senderPrivateKey,
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
                `Recipient Internet address is malformed ("${malformedDomainName}")`,
              ),
            );
          });
        });
      });

      describe('Message id', () => {
        test('Id should be deserialized', async () => {
          const id = 'a'.repeat(64);
          const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD, { id });
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

        test('Id should not exceed 64 characters', async () => {
          const id = 'a'.repeat(65);
          const messageSerialized = await serializeRamfWithoutValidation([
            new Sequence({ value: [new VisibleString({ value: RECIPIENT_ID })] }),
            new VisibleString({ value: id }),
            dateToASN1DateTimeInUTC(NOW),
            new Integer({ value: 1_000 }),
            new OctetString({ valueHex: new ArrayBuffer(0) }),
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
            new Sequence({ value: [new VisibleString({ value: RECIPIENT_ID })] }),
            new VisibleString({ value: 'id' }),
            new DateTime({ value: date }),
            new Integer({ value: 1_000 }),
            new OctetString({ valueHex: new ArrayBuffer(0) }),
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
            new Sequence({ value: [new VisibleString({ value: 'the-address' })] }),
            new VisibleString({ value: 'id' }),
            new DateTime({ value: '42' }),
            new Integer({ value: 1_000 }),
            new OctetString({ valueHex: new ArrayBuffer(0) }),
          ]);

          await expect(
            deserialize(
              messageSerialized,
              stubConcreteMessageTypeOctet,
              stubConcreteMessageVersionOctet,
              StubMessage,
            ),
          ).rejects.toThrowWithMessage(RAMFValidationError, /^Message date is invalid:/);
        });
      });

      describe('TTL', () => {
        test('TTL of exactly 180 days should be accepted', async () => {
          const messageSerialized = await serializeRamfWithoutValidation([
            new Sequence({ value: [new VisibleString({ value: RECIPIENT_ID })] }),
            new VisibleString({ value: 'the-id' }),
            dateToASN1DateTimeInUTC(NOW),
            new Integer({ value: MAX_TTL }),
            new OctetString({ valueHex: new ArrayBuffer(0) }),
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
            new Sequence({ value: [new VisibleString({ value: RECIPIENT_ID })] }),
            new VisibleString({ value: 'the-id' }),
            dateToASN1DateTimeInUTC(NOW),
            new Integer({ value: MAX_TTL + 1 }),
            new OctetString({ valueHex: new ArrayBuffer(0) }),
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
          const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);
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

        test('Payload size should not exceed 8 MiB', async () => {
          const largePayload = Buffer.from('a'.repeat(MAX_PAYLOAD_LENGTH + 1));
          const messageSerialized = await serializeRamfWithoutValidation([
            new Sequence({ value: [new VisibleString({ value: RECIPIENT_ID })] }),
            new VisibleString({ value: 'the-id' }),
            dateToASN1DateTimeInUTC(NOW),
            new Integer({ value: 1_000 }),
            new OctetString({ valueHex: bufferToArray(largePayload) }),
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
      const message = new StubMessage(RECIPIENT, senderCertificate, PAYLOAD);
      const messageSerialized = await serialize(
        message,
        stubConcreteMessageTypeOctet,
        stubConcreteMessageVersionOctet,
        senderPrivateKey,
      );

      jest.spyOn(cmsSignedData, 'verifySignature');
      const messageDeserialized = await deserialize(
        messageSerialized,
        stubConcreteMessageTypeOctet,
        stubConcreteMessageVersionOctet,
        StubMessage,
      );

      expect(messageDeserialized.recipient).toEqual(message.recipient);
      expect(messageDeserialized.senderCertificate.isEqual(message.senderCertificate)).toBeTrue();
      expect(messageDeserialized.payloadSerialized).toEqual(message.payloadSerialized);
    });

    async function serializeRamfWithoutValidation(
      sequenceItems: ReadonlyArray<BaseBlock<any>>,
      customSenderCertificate?: Certificate,
    ): Promise<ArrayBuffer> {
      const serializer = new SmartBuffer();
      serializer.writeString('Awala');
      serializer.writeUInt8(stubConcreteMessageTypeOctet);
      serializer.writeUInt8(stubConcreteMessageVersionOctet);

      const signedData = await cmsSignedData.SignedData.sign(
        makeImplicitlyTaggedSequence(...sequenceItems).toBER(),
        senderPrivateKey,
        customSenderCertificate ?? senderCertificate,
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
    concreteMessageType: buffer.readUInt8(5),
    concreteMessageVersion: buffer.readUInt8(6),
    magic: buffer.slice(0, 5).toString(),
  };
}
