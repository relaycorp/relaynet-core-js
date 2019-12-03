/* tslint:disable:no-let max-classes-per-file */
import bufferToArray from 'buffer-to-arraybuffer';
import { SmartBuffer } from 'smart-buffer';

import { expectPromiseToReject, generateStubCert } from '../_test_utils';
import * as cms from '../cms';
import { generateRsaKeys } from '../crypto';
import Certificate from '../pki/Certificate';
import {
  MESSAGE_PARSER,
  NON_ASCII_STRING,
  STUB_MESSAGE_SERIALIZER,
  StubMessage,
  StubPayload
} from './_test_utils';
import { MessageSerializer } from './MessageSerializer';
import RAMFError from './RAMFError';

const mockStubUuid4 = '56e95d8a-6be2-4020-bb36-5dd0da36c181';
jest.mock('uuid4', () => {
  return {
    __esModule: true,
    default: jest.fn().mockImplementation(() => mockStubUuid4)
  };
});

const payload = bufferToArray(Buffer.from('Hi'));

afterEach(() => {
  jest.restoreAllMocks();
});

describe('MessageSerializer', () => {
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

  describe('serialize', () => {
    describe('Format signature', () => {
      let stubMessage: StubMessage;
      beforeAll(() => {
        stubMessage = new StubMessage(recipientAddress, senderCertificate, payload);
      });

      test('The ASCII string "Relaynet" should be at the start', async () => {
        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(Buffer.from(messageSerialized));
        expect(messageParts).toHaveProperty('magic', 'Relaynet');
      });

      test('The concrete message type should be represented with an octet', async () => {
        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(Buffer.from(messageSerialized));
        expect(messageParts).toHaveProperty(
          'concreteMessageSignature',
          STUB_MESSAGE_SERIALIZER.concreteMessageTypeOctet
        );
      });

      test('The concrete message version should be at the end', async () => {
        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(Buffer.from(messageSerialized));
        expect(messageParts).toHaveProperty(
          'concreteMessageVersion',
          STUB_MESSAGE_SERIALIZER.concreteMessageVersionOctet
        );
      });
    });

    describe('Recipient address', () => {
      test('Address should be serialized with length prefix', async () => {
        const address = recipientCertificate.getAddress();
        const stubMessage = new StubMessage(address, senderCertificate, payload);

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(Buffer.from(messageSerialized));
        expect(messageParts).toHaveProperty('recipientAddressLength', address.length);
        expect(messageParts).toHaveProperty('recipientAddress', address);
      });

      test('Address should be representable with 10 bits', async () => {
        const address = 'a'.repeat(2 ** 10 - 1);
        const stubMessage = new StubMessage(address, senderCertificate, payload);

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(Buffer.from(messageSerialized));
        expect(messageParts).toHaveProperty('recipientAddress', address);
      });

      test('Address should not exceed 10 bits length', async () => {
        const invalidAddress = 'a'.repeat(2 ** 10);
        const stubMessage = new StubMessage(invalidAddress, senderCertificate, payload);

        await expectPromiseToReject(
          STUB_MESSAGE_SERIALIZER.serialize(stubMessage, senderPrivateKey, recipientCertificate),
          new RAMFError('Recipient address exceeds maximum length')
        );
      });

      test('Non-ASCII addresses should be UTF-8 encoded', async () => {
        const stubMessage = new StubMessage(NON_ASCII_STRING, senderCertificate, payload);

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(Buffer.from(messageSerialized));
        expect(messageParts).toHaveProperty('recipientAddress', NON_ASCII_STRING);
      });

      test('Multi-byte characters should be accounted for in length validation', async () => {
        const invalidAddress = '❤'.repeat(2 ** 10 - 1);
        const stubMessage = new StubMessage(invalidAddress, senderCertificate, payload);

        await expectPromiseToReject(
          STUB_MESSAGE_SERIALIZER.serialize(stubMessage, senderPrivateKey, recipientCertificate),
          new RAMFError('Recipient address exceeds maximum length')
        );
      });
    });

    describe('Message id', () => {
      test('Id should be up to 8 bits long', async () => {
        const idLength = 2 ** 8 - 1;
        const id = 'a'.repeat(idLength);
        const stubMessage = new StubMessage(recipientAddress, senderCertificate, payload, { id });

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(Buffer.from(messageSerialized));
        expect(messageParts).toHaveProperty('messageIdLength', idLength);
        expect(messageParts).toHaveProperty('messageId', stubMessage.id);
      });

      test('A custom id with a length greater than 8 bits should be refused', async () => {
        const id = 'a'.repeat(2 ** 8);
        const stubMessage = new StubMessage(recipientAddress, senderCertificate, payload, { id });

        await expectPromiseToReject(
          STUB_MESSAGE_SERIALIZER.serialize(stubMessage, senderPrivateKey, recipientCertificate),
          new RAMFError('Custom id exceeds maximum length')
        );
      });

      test('Id should be ASCII-encoded', async () => {
        const stubMessage = new StubMessage(recipientAddress, senderCertificate, payload, {
          id: NON_ASCII_STRING
        });

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(Buffer.from(messageSerialized));
        const expectedId = Buffer.from(NON_ASCII_STRING, 'ascii').toString('ascii');
        expect(messageParts).toHaveProperty('messageId', expectedId);
      });
    });

    describe('Date', () => {
      test('Date should be serialized as 32-bit unsigned integer', async () => {
        const stubMessage = new StubMessage(recipientAddress, senderCertificate, payload);

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(Buffer.from(messageSerialized));
        const expectedTimestamp = Math.floor(stubMessage.date.getTime() / 1000);
        expect(messageParts).toHaveProperty('date', expectedTimestamp);
      });

      test('Date should not be before Unix epoch', async () => {
        const invalidDate = new Date(1969, 11, 31, 23, 59, 59);
        const stubMessage = new StubMessage(recipientAddress, senderCertificate, payload, {
          date: invalidDate
        });

        await expectPromiseToReject(
          STUB_MESSAGE_SERIALIZER.serialize(stubMessage, senderPrivateKey, recipientCertificate),
          new RAMFError('Date cannot be before Unix epoch')
        );
      });

      test('Timestamp should be less than 2 ^ 32', async () => {
        const invalidDate = new Date(2 ** 32 * 1000);
        const stubMessage = new StubMessage(recipientAddress, senderCertificate, payload, {
          date: invalidDate
        });

        await expectPromiseToReject(
          STUB_MESSAGE_SERIALIZER.serialize(stubMessage, senderPrivateKey, recipientCertificate),
          new RAMFError('Date timestamp cannot be represented with 32 bits')
        );
      });

      test('Date should be serialized as UTC', async () => {
        const date = new Date('01 Jan 2019 12:00:00 GMT+11:00');
        const message = new StubMessage(recipientAddress, senderCertificate, payload, { date });

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );

        const messageParts = MESSAGE_PARSER.parse(Buffer.from(messageSerialized));
        expect(messageParts).toHaveProperty('date', date.getTime() / 1_000);
      });
    });

    describe('TTL', () => {
      test('TTL should be serialized as 24-bit unsigned integer', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload);

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(Buffer.from(messageSerialized));
        expect(parse24BitNumber(messageParts.ttlBuffer)).toEqual(message.ttl);
      });

      test('TTL of zero should be accepted', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload, { ttl: 0 });

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );

        const messageParts = MESSAGE_PARSER.parse(Buffer.from(messageSerialized));
        expect(parse24BitNumber(messageParts.ttlBuffer)).toEqual(0);
      });

      test('TTL should not be negative', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload, {
          ttl: -1
        });
        await expectPromiseToReject(
          STUB_MESSAGE_SERIALIZER.serialize(message, senderPrivateKey, recipientCertificate),
          new RAMFError('TTL cannot be negative')
        );
      });

      test('TTL should not be more than 24 bits long', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload, {
          ttl: 2 ** 24
        });
        await expectPromiseToReject(
          STUB_MESSAGE_SERIALIZER.serialize(message, senderPrivateKey, recipientCertificate),
          new RAMFError('TTL must be less than 2^24')
        );
      });
    });

    describe('Payload', () => {
      test('Payload should be encrypted', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload);
        jest.spyOn(cms, 'encrypt');

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );

        expect(cms.encrypt).toBeCalledTimes(1);
        expect(cms.encrypt).toBeCalledWith(StubPayload.BUFFER, recipientCertificate, undefined);

        const messageParts = MESSAGE_PARSER.parse(Buffer.from(messageSerialized));
        const payloadCiphertext = messageParts.payload;
        expect(await cms.decrypt(bufferToArray(payloadCiphertext), recipientPrivateKey)).toEqual(
          StubPayload.BUFFER
        );
      });

      test('Encryption options should be honoured', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload);
        jest.spyOn(cms, 'encrypt');

        const encryptionOptions = { aesKeySize: 256 };
        await STUB_MESSAGE_SERIALIZER.serialize(
          message,
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
        const message = new StubMessage(recipientAddress, senderCertificate, payload, {
          senderCertificateChain
        });

        jest.spyOn(cms, 'sign');
        serialization = Buffer.from(
          await STUB_MESSAGE_SERIALIZER.serialize(message, senderPrivateKey, recipientCertificate)
        );
        expect(cms.sign).toBeCalledTimes(1);
        // @ts-ignore
        cmsSignArgs = cms.sign.mock.calls[0];

        const messageParts = MESSAGE_PARSER.parse(serialization);
        signature = messageParts.signature;
      });

      test('Plaintext should be preceding RAMF message octets', () => {
        const plaintext = Buffer.from(cmsSignArgs[0]);
        const expectedPlaintextLength = serialization.length - 2 - signature.length;
        const expectedPlaintext = serialization.slice(0, expectedPlaintextLength);

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
        const message = new StubMessage(recipientAddress, senderCertificate, payload);
        const mockSignature = new ArrayBuffer(0);
        jest.spyOn(mockSignature, 'byteLength', 'get').mockReturnValue(2 ** 16);
        jest.spyOn(cms, 'sign').mockReturnValue(Promise.resolve(mockSignature));

        await expectPromiseToReject(
          STUB_MESSAGE_SERIALIZER.serialize(message, senderPrivateKey, recipientCertificate),
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
          const message = new StubMessage(recipientAddress, senderCertificate, payload);

          jest.spyOn(cms, 'sign');
          await STUB_MESSAGE_SERIALIZER.serialize(message, senderPrivateKey, recipientCertificate, {
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

  describe('deserialize', () => {
    describe('Format signature', () => {
      test('Input should be refused if it does not start with "Relaynet"', async () => {
        const serialization = bufferToArray(Buffer.from('Relaycorp'));
        await expectPromiseToReject(
          STUB_MESSAGE_SERIALIZER.deserialize(serialization, recipientPrivateKey),
          new RAMFError('Serialization is not a valid RAMF message: Relaynet is not defined')
        );
      });

      test('A non-matching concrete message type should be refused', async () => {
        const altSerializer = new MessageSerializer<StubMessage>(
          StubMessage,
          STUB_MESSAGE_SERIALIZER.concreteMessageTypeOctet + 1,
          STUB_MESSAGE_SERIALIZER.concreteMessageVersionOctet
        );
        const altMessage = new StubMessage(recipientAddress, senderCertificate, payload);
        const serialization = await altSerializer.serialize(
          altMessage,
          senderPrivateKey,
          recipientCertificate
        );

        await expectPromiseToReject(
          STUB_MESSAGE_SERIALIZER.deserialize(serialization, recipientPrivateKey),
          new RAMFError('Expected concrete message type 0x44 but got 0x45')
        );
      });

      test('A non-matching concrete message version should be refused', async () => {
        const altSerializer = new MessageSerializer<StubMessage>(
          StubMessage,
          STUB_MESSAGE_SERIALIZER.concreteMessageTypeOctet,
          STUB_MESSAGE_SERIALIZER.concreteMessageVersionOctet + 1
        );
        const altMessage = new StubMessage(recipientAddress, senderCertificate, payload);
        const serialization = await altSerializer.serialize(
          altMessage,
          senderPrivateKey,
          recipientCertificate
        );

        await expectPromiseToReject(
          STUB_MESSAGE_SERIALIZER.deserialize(serialization, recipientPrivateKey),
          new RAMFError('Expected concrete message version 0x2 but got 0x3')
        );
      });
    });

    describe('Recipient address', () => {
      test('Address should be serialized with length prefix', async () => {
        const address = 'a'.repeat(2 ** 10 - 1);
        const message = new StubMessage(address, senderCertificate, payload);
        const serialization = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );
        const deserialization = await STUB_MESSAGE_SERIALIZER.deserialize(
          serialization,
          recipientPrivateKey
        );
        expect(deserialization.recipientAddress).toEqual(address);
      });

      test('Length prefix should not exceed 10 bits', async () => {
        const address = 'a'.repeat(2 ** 10);
        const messageSerialized = serializeWithoutValidation({ address });
        await expectPromiseToReject(
          STUB_MESSAGE_SERIALIZER.deserialize(messageSerialized, recipientPrivateKey),
          new RAMFError('Recipient address exceeds maximum length')
        );
      });

      test('Address should be UTF-8 encoded', async () => {
        const address = `scheme://${NON_ASCII_STRING}.com`;
        const message = new StubMessage(address, senderCertificate, payload);
        const serialization = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );
        const deserialization = await STUB_MESSAGE_SERIALIZER.deserialize(
          serialization,
          recipientPrivateKey
        );
        expect(deserialization.recipientAddress).toEqual(address);
      });
    });

    describe('Message id', () => {
      test('Id should be serialized with length prefix', async () => {
        const id = 'a'.repeat(2 ** 8 - 1);
        const message = new StubMessage(recipientAddress, senderCertificate, payload, { id });
        const serialization = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );
        const deserialization = await STUB_MESSAGE_SERIALIZER.deserialize(
          serialization,
          recipientPrivateKey
        );
        expect(deserialization.id).toEqual(id);
      });

      test('Id should be ASCII-encoded', async () => {
        const id = NON_ASCII_STRING;
        const message = new StubMessage(recipientAddress, senderCertificate, payload, { id });
        const serialization = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );
        const deserialization = await STUB_MESSAGE_SERIALIZER.deserialize(
          serialization,
          recipientPrivateKey
        );
        const expectedId = Buffer.from(id, 'ascii').toString('ascii');
        expect(deserialization.id).toEqual(expectedId);
      });
    });

    describe('Date', () => {
      test('Date should be serialized as 32-bit unsigned integer', async () => {
        const maxTimestampSec = 2 ** 32 - 1;
        const maxTimestampMs = maxTimestampSec * 1000;
        const date = new Date(maxTimestampMs);
        const message = new StubMessage(recipientAddress, senderCertificate, payload, { date });
        const serialization = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );
        const deserialization = await STUB_MESSAGE_SERIALIZER.deserialize(
          serialization,
          recipientPrivateKey
        );
        expect(deserialization.date).toEqual(date);
      });
    });

    describe('TTL', () => {
      test('TTL should be serialized as 24-bit unsigned integer', async () => {
        const ttl = 2 ** 24 - 1;
        const message = new StubMessage(recipientAddress, senderCertificate, payload, { ttl });
        const serialization = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );
        const deserialization = await STUB_MESSAGE_SERIALIZER.deserialize(
          serialization,
          recipientPrivateKey
        );
        expect(deserialization.ttl).toEqual(ttl);
      });
    });

    describe('Payload', () => {
      test('Payload should be decrypted', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload);
        jest.spyOn(cms, 'encrypt');
        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );

        jest.spyOn(cms, 'decrypt');
        const messageDeserialized = await STUB_MESSAGE_SERIALIZER.deserialize(
          messageSerialized,
          recipientPrivateKey
        );

        // @ts-ignore
        const payloadCiphertext = cms.encrypt.results[0];
        expect(cms.decrypt).toBeCalledWith(payloadCiphertext, recipientPrivateKey);

        expect(messageDeserialized.exportPayload()).toEqual(payload);
      });
    });

    describe('Signature', () => {
      test('Signature should be serialized with length prefix', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload);
        jest.spyOn(cms, 'sign');
        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );

        jest.spyOn(cms, 'verifySignature');
        const messageDeserialized = await STUB_MESSAGE_SERIALIZER.deserialize(
          messageSerialized,
          recipientPrivateKey
        );

        // @ts-ignore
        const signatureCiphertext = cms.sign.results[0];
        expect(cms.verifySignature).toBeCalledWith(signatureCiphertext, recipientPrivateKey);

        expect(messageDeserialized.senderCertificate).toBe(senderCertificate);
      });

      test('Length prefix should not exceed 14 bits', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload);

        jest
          .spyOn(cms, 'sign')
          .mockImplementationOnce(async () => bufferToArray(Buffer.from('a'.repeat(2 ** 14))));
        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );

        await expectPromiseToReject(
          STUB_MESSAGE_SERIALIZER.deserialize(messageSerialized, recipientPrivateKey),
          new RAMFError('Signature exceeds maximum length')
        );
      });

      test.todo('Sender certificate chain should be retrieved');
    });
  });

  function serializeWithoutValidation({
    address = 'random address',
    date = new Date(),
    id = 'random id',
    messageType = STUB_MESSAGE_SERIALIZER.concreteMessageTypeOctet,
    messageVersion = STUB_MESSAGE_SERIALIZER.concreteMessageVersionOctet,
    payloadBuffer = payload,
    signature = Buffer.from('Looks alright'),
    ttl = 1
  }): ArrayBuffer {
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

    serialization.writeUInt16LE(signature.byteLength);
    serialization.writeBuffer(signature);

    return bufferToArray(serialization.toBuffer());
  }
});

function parse24BitNumber(buffer: Buffer): number {
  return buffer.readUIntLE(0, 3);
}
