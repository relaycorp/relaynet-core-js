/* tslint:disable:no-let max-classes-per-file */
import bufferToArray from 'buffer-to-arraybuffer';

import { expectPromiseToReject, generateStubCert } from '../_test_utils';
import * as cms from '../cms';
import { generateRsaKeys } from '../crypto';
import Certificate from '../pki/Certificate';
import {
  MESSAGE_PARSER,
  NON_ASCII_STRING,
  STUB_MESSAGE_SERIALIZER,
  STUB_UUID4,
  StubMessage,
  StubPayload
} from './_test_utils';
import RAMFError from './RAMFError';

jest.mock('uuid4', () => {
  return {
    __esModule: true,
    default: jest.fn().mockImplementation(() => STUB_UUID4)
  };
});

const payload = new StubPayload();

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
        stubMessage = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload
        );
      });

      test('The ASCII string "Relaynet" should be at the start', async () => {
        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(
          Buffer.from(messageSerialized)
        );
        expect(messageParts).toHaveProperty('magic', 'Relaynet');
      });

      test('The concrete message type should be represented with an octet', async () => {
        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(
          Buffer.from(messageSerialized)
        );
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
        const messageParts = MESSAGE_PARSER.parse(
          Buffer.from(messageSerialized)
        );
        expect(messageParts).toHaveProperty(
          'concreteMessageVersion',
          STUB_MESSAGE_SERIALIZER.concreteMessageVersionOctet
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

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(
          Buffer.from(messageSerialized)
        );
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

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(
          Buffer.from(messageSerialized)
        );
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

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(
          Buffer.from(messageSerialized)
        );
        expect(messageParts).toHaveProperty(
          'messageIdLength',
          STUB_UUID4.length
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

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(
          Buffer.from(messageSerialized)
        );
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

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          stubMessage,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(
          Buffer.from(messageSerialized)
        );
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

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );
        const messageParts = MESSAGE_PARSER.parse(
          Buffer.from(messageSerialized)
        );
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

        const messageSerialized = await STUB_MESSAGE_SERIALIZER.serialize(
          message,
          senderPrivateKey,
          recipientCertificate
        );

        expect(cms.encrypt).toBeCalledTimes(1);
        expect(cms.encrypt).toBeCalledWith(
          StubPayload.BUFFER,
          recipientCertificate,
          undefined
        );

        const messageParts = MESSAGE_PARSER.parse(
          Buffer.from(messageSerialized)
        );
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
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          payload,
          { senderCertificateChain }
        );

        jest.spyOn(cms, 'sign');
        serialization = Buffer.from(
          await STUB_MESSAGE_SERIALIZER.serialize(
            message,
            senderPrivateKey,
            recipientCertificate
          )
        );
        expect(cms.sign).toBeCalledTimes(1);
        // @ts-ignore
        cmsSignArgs = cms.sign.mock.calls[0];

        const messageParts = MESSAGE_PARSER.parse(serialization);
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
          STUB_MESSAGE_SERIALIZER.serialize(
            message,
            senderPrivateKey,
            recipientCertificate
          ),
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
          await STUB_MESSAGE_SERIALIZER.serialize(
            message,
            senderPrivateKey,
            recipientCertificate,
            {
              hashingAlgorithmName
            }
          );
          expect(cms.sign).toBeCalledTimes(1);
          // @ts-ignore
          const signatureArgs = cms.sign.mock.calls[0];
          expect(signatureArgs[4]).toEqual({ hashingAlgorithmName });
        }
      );
    });
  });
});
