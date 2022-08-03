// tslint:disable:max-classes-per-file

import { addMinutes, addSeconds, setMilliseconds, subSeconds } from 'date-fns';
import * as jestDateMock from 'jest-date-mock';

import { generateStubCert, reSerializeCertificate } from '../_test_utils';
import {
  SessionEnvelopedData,
  SessionlessEnvelopedData,
} from '../crypto_wrappers/cms/envelopedData';
import { generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import CertificateError from '../crypto_wrappers/x509/CertificateError';
import { MockPrivateKeyStore } from '../keyStores/testMocks';
import { StubMessage, StubPayload } from '../ramf/_test_utils';
import RAMFError from '../ramf/RAMFError';
import { SessionKeyPair } from '../SessionKeyPair';
import InvalidMessageError from './InvalidMessageError';
import { Recipient } from './Recipient';

const mockStubUuid4 = '56e95d8a-6be2-4020-bb36-5dd0da36c181';
jest.mock('uuid4', () => {
  return {
    __esModule: true,
    default: jest.fn().mockImplementation(() => mockStubUuid4),
  };
});

const STUB_PAYLOAD_PLAINTEXT = Buffer.from('Hi');

afterEach(() => {
  jest.restoreAllMocks();
  jestDateMock.clear();
});

describe('RAMFMessage', () => {
  let rootCertificate: Certificate;
  let senderCertificate: Certificate;
  let recipientCertificate: Certificate;
  let recipient: Recipient;
  beforeAll(async () => {
    const stubSenderChain = await generateAuthorizedSenderChain();

    rootCertificate = stubSenderChain.rootCert;
    recipientCertificate = stubSenderChain.recipientCert;
    senderCertificate = stubSenderChain.senderCert;

    recipient = { id: recipientCertificate.getCommonName() };
  });

  describe('constructor', () => {
    describe('Id', () => {
      test('Id should fall back to UUID4 when left unspecified', () => {
        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT);

        expect(message.id).toEqual(mockStubUuid4);
      });
    });

    describe('Date', () => {
      test('The current date (UTC) should be used by default', () => {
        const now = new Date(2019, 1, 1, 1, 1, 1, 1);
        jestDateMock.advanceTo(now);

        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT);

        const expectedDate = setMilliseconds(now, 0);
        expect(message.creationDate).toEqual(expectedDate);
      });

      test('A custom date should be accepted', () => {
        const date = new Date(2020, 1, 1, 1, 1, 1, 1);

        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT, {
          creationDate: date,
        });

        const expectedDate = new Date(date.getTime());
        expectedDate.setMilliseconds(0);
        expect(message.creationDate).toEqual(expectedDate);
      });
    });

    describe('TTL', () => {
      test('TTL should be 5 minutes by default', () => {
        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT);

        expect(message.ttl).toEqual(5 * 60);
      });

      test('A custom TTL under 2^24 should be accepted', () => {
        const ttl = 2 ** 24 - 1;
        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT, {
          ttl,
        });

        expect(message.ttl).toEqual(ttl);
      });
    });

    describe('Sender CA certificate chain', () => {
      test('CA certificate chain should be empty by default', () => {
        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT);

        expect(message.senderCaCertificateChain).toEqual([]);
      });

      test('A custom sender certificate chain should be accepted', async () => {
        const chain: readonly Certificate[] = [await generateStubCert(), await generateStubCert()];
        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT, {
          senderCaCertificateChain: chain,
        });

        expect(message.senderCaCertificateChain).toEqual(chain);
      });

      test('Sender certificate should be excluded from chain if included', async () => {
        const chain: readonly Certificate[] = [await generateStubCert()];
        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT, {
          senderCaCertificateChain: [...chain, senderCertificate],
        });

        expect(message.senderCaCertificateChain).toEqual(chain);
      });
    });
  });

  test('getSenderCertificationPath should return certification path', async () => {
    const message = new StubMessage(
      { id: await recipientCertificate.calculateSubjectId() },
      senderCertificate,
      STUB_PAYLOAD_PLAINTEXT,
      {
        senderCaCertificateChain: [recipientCertificate],
      },
    );

    await expect(message.getSenderCertificationPath([rootCertificate])).resolves.toEqual([
      expect.toSatisfy((c) => c.isEqual(senderCertificate)),
      expect.toSatisfy((c) => c.isEqual(recipientCertificate)),
      expect.toSatisfy((c) => c.isEqual(rootCertificate)),
    ]);
  });

  test('expiryDate field should calculate expiry date from creation date and TTL', () => {
    const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT, {
      creationDate: new Date('2020-04-07T21:00:00Z'),
      ttl: 5,
    });

    const expectedExpiryDate = new Date(message.creationDate.getTime());
    expectedExpiryDate.setSeconds(expectedExpiryDate.getSeconds() + message.ttl);
    expect(message.expiryDate).toEqual(expectedExpiryDate);
  });

  describe('validate', () => {
    describe('Authorization without trusted certificates', () => {
      test('Invalid sender certificate should be refused', async () => {
        const invalidSenderCertificate = await generateStubCert({
          attributes: { validityStartDate: addMinutes(new Date(), 1) },
        });
        const message = new StubMessage(
          recipient,
          invalidSenderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
        );

        await expect(message.validate()).rejects.toBeInstanceOf(CertificateError);
      });

      test('Valid sender certificate should be allowed', async () => {
        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT);

        await expect(message.validate()).resolves.toBeNull();
      });

      test('Mismatching recipient should be allowed', async () => {
        const message = new StubMessage(
          { id: `not-${recipient.id}` },
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
        );

        await expect(message.validate()).resolves.toBeNull();
      });
    });

    describe('Authorization with trusted certificates', () => {
      test('Message should be refused if sender is not trusted', async () => {
        // The intermediate certificate is missing
        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT);

        await expect(message.validate([rootCertificate])).rejects.toEqual(
          new InvalidMessageError('Sender is not authorized: No valid certificate paths found'),
        );
      });

      test('Message should be accepted if sender is trusted', async () => {
        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT, {
          senderCaCertificateChain: [recipientCertificate],
        });

        const certificationPath = await message.validate([rootCertificate]);
        expect(certificationPath).toHaveLength(3);
        expect(certificationPath!![0].isEqual(message.senderCertificate)).toBeTrue();
        expect(certificationPath!![1].isEqual(recipientCertificate)).toBeTrue();
        expect(certificationPath!![2].isEqual(rootCertificate)).toBeTrue();
      });

      test('Message should be refused if recipient does not match issuer of sender', async () => {
        const message = new StubMessage(
          { id: `not-${recipient.id}` },
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
          {
            senderCaCertificateChain: [recipientCertificate],
          },
        );

        await expect(message.validate([rootCertificate])).rejects.toEqual(
          new InvalidMessageError(`Sender is not authorized to reach ${message.recipient.id}`),
        );
      });
    });

    describe('Validity period', () => {
      test('Date equal to the current date should be accepted', async () => {
        const stubDate = setMilliseconds(subSeconds(senderCertificate.expiryDate, 1), 0);
        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT, {
          creationDate: stubDate,
        });
        jestDateMock.advanceTo(stubDate);

        await message.validate();
      });

      test('Date should not be in the future', async () => {
        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT, {
          creationDate: setMilliseconds(new Date(), 0),
        });
        jestDateMock.advanceTo(subSeconds(message.creationDate, 1));

        await expect(message.validate()).rejects.toEqual(
          new InvalidMessageError('Message date is in the future'),
        );
      });

      test('TTL matching current time should be accepted', async () => {
        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT, {
          creationDate: senderCertificate.startDate,
          ttl: 1,
        });
        jestDateMock.advanceTo(message.expiryDate);

        await message.validate();
      });

      test('TTL in the past should not be accepted', async () => {
        const message = new StubMessage(recipient, senderCertificate, STUB_PAYLOAD_PLAINTEXT, {
          ttl: 1,
        });
        jestDateMock.advanceTo(addSeconds(message.expiryDate, 1));

        await expect(message.validate()).rejects.toEqual(
          new InvalidMessageError('Message already expired'),
        );
      });
    });
  });

  describe('unwrapPayload', () => {
    test('SessionlessEnvelopedData payload should be unsupported', async () => {
      const envelopedData = await SessionlessEnvelopedData.encrypt(
        STUB_PAYLOAD_PLAINTEXT,
        recipientCertificate,
      );

      const recipientKeyStore = new MockPrivateKeyStore();

      const stubMessage = new StubMessage(
        recipient,
        senderCertificate,
        Buffer.from(envelopedData.serialize()),
      );

      await expect(stubMessage.unwrapPayload(recipientKeyStore)).rejects.toThrowWithMessage(
        RAMFError,
        'Sessionless payloads are no longer supported',
      );
    });

    test('Payload should be decrypted with key store', async () => {
      const recipientSessionKeyPair = await SessionKeyPair.generate();
      const { envelopedData } = await SessionEnvelopedData.encrypt(
        STUB_PAYLOAD_PLAINTEXT,
        recipientSessionKeyPair.sessionKey,
      );
      const stubMessage = new StubMessage(
        recipient,
        senderCertificate,
        Buffer.from(envelopedData.serialize()),
      );
      const recipientKeyStore = new MockPrivateKeyStore();
      await recipientKeyStore.saveSessionKey(
        recipientSessionKeyPair.privateKey,
        recipientSessionKeyPair.sessionKey.keyId,
        recipient.id,
      );

      const { payload, senderSessionKey } = await stubMessage.unwrapPayload(recipientKeyStore);

      expect(payload).toBeInstanceOf(StubPayload);
      expect(Buffer.from(payload.content)).toEqual(STUB_PAYLOAD_PLAINTEXT);

      expect(senderSessionKey).toEqual(await envelopedData.getOriginatorKey());
    });

    test('Payload should be decrypted with private key', async () => {
      const recipientSessionKeyPair = await SessionKeyPair.generate();
      const { envelopedData } = await SessionEnvelopedData.encrypt(
        STUB_PAYLOAD_PLAINTEXT,
        recipientSessionKeyPair.sessionKey,
      );

      const stubMessage = new StubMessage(
        recipient,
        senderCertificate,
        Buffer.from(envelopedData.serialize()),
      );

      const { payload } = await stubMessage.unwrapPayload(recipientSessionKeyPair.privateKey);

      expect(payload).toBeInstanceOf(StubPayload);
      expect(Buffer.from(payload.content)).toEqual(STUB_PAYLOAD_PLAINTEXT);
    });
  });
});

interface AuthorizedSenderChain {
  readonly rootCert: Certificate;
  readonly recipientCert: Certificate;
  readonly senderCert: Certificate;
}

async function generateAuthorizedSenderChain(): Promise<AuthorizedSenderChain> {
  const rootKeyPair = await generateRSAKeyPair();
  const rootCert = reSerializeCertificate(
    await generateStubCert({
      attributes: { isCA: true },
      issuerPrivateKey: rootKeyPair.privateKey,
      subjectPublicKey: rootKeyPair.publicKey,
    }),
  );

  const recipientKeyPair = await generateRSAKeyPair();
  const recipientCert = reSerializeCertificate(
    await generateStubCert({
      attributes: { isCA: true },
      issuerCertificate: rootCert,
      issuerPrivateKey: rootKeyPair.privateKey,
      subjectPublicKey: recipientKeyPair.publicKey,
    }),
  );

  const senderCert = reSerializeCertificate(
    await generateStubCert({
      attributes: { isCA: false },
      issuerCertificate: recipientCert,
      issuerPrivateKey: recipientKeyPair.privateKey,
    }),
  );

  return { recipientCert, rootCert, senderCert };
}
