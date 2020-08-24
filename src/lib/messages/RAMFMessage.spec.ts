/* tslint:disable:no-let max-classes-per-file */
import bufferToArray from 'buffer-to-arraybuffer';
import * as jestDateMock from 'jest-date-mock';

import { generateStubCert, reSerializeCertificate } from '../_test_utils';
import {
  SessionEnvelopedData,
  SessionlessEnvelopedData,
} from '../crypto_wrappers/cms/envelopedData';
import { generateECDHKeyPair, generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { MockPrivateKeyStore } from '../keyStores/testMocks';
import { issueInitialDHKeyCertificate } from '../pki';
import { StubMessage, StubPayload } from '../ramf/_test_utils';
import InvalidMessageError from './InvalidMessageError';

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
  let recipientPrivateAddress: string;
  let recipientCertificate: Certificate;
  let recipientPrivateKey: CryptoKey;
  let senderCertificate: Certificate;
  beforeAll(async () => {
    const recipientKeyPair = await generateRSAKeyPair();
    recipientCertificate = await generateStubCert({
      attributes: { isCA: true },
      subjectPublicKey: recipientKeyPair.publicKey,
    });
    recipientPrivateKey = recipientKeyPair.privateKey;
    recipientPrivateAddress = recipientCertificate.getCommonName();

    const senderKeyPair = await generateRSAKeyPair();
    senderCertificate = await generateStubCert({
      subjectPublicKey: senderKeyPair.publicKey,
    });
  });

  let stubSenderChain: AuthorizedSenderChain;
  beforeAll(async () => {
    stubSenderChain = await generateAuthorizedSenderChain();
  });

  describe('constructor', () => {
    describe('Id', () => {
      test('Id should fall back to UUID4 when left unspecified', () => {
        const message = new StubMessage(
          recipientPrivateAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
        );

        expect(message.id).toEqual(mockStubUuid4);
      });
    });

    describe('Date', () => {
      test('The current date (UTC) should be used by default', () => {
        const now = new Date(2019, 1, 1, 1, 1, 1, 1);
        jestDateMock.advanceTo(now);

        const message = new StubMessage(
          recipientPrivateAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
        );

        expect(message.creationDate).toEqual(now);
      });

      test('A custom date should be accepted', () => {
        const date = new Date(2020, 1, 1, 1, 1, 1, 1);

        const message = new StubMessage(
          recipientPrivateAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
          { creationDate: date },
        );

        expect(message.creationDate).toEqual(date);
      });
    });

    describe('TTL', () => {
      test('TTL should be 5 minutes by default', () => {
        const message = new StubMessage(
          recipientPrivateAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
        );

        expect(message.ttl).toEqual(5 * 60);
      });

      test('A custom TTL under 2^24 should be accepted', () => {
        const ttl = 2 ** 24 - 1;
        const message = new StubMessage(
          recipientPrivateAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
          { ttl },
        );

        expect(message.ttl).toEqual(ttl);
      });
    });

    describe('Sender CA certificate chain', () => {
      test('CA certificate chain should be empty by default', () => {
        const message = new StubMessage(
          recipientPrivateAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
        );

        expect(message.senderCaCertificateChain).toEqual([]);
      });

      test('A custom sender certificate chain should be accepted', async () => {
        const chain: readonly Certificate[] = [await generateStubCert(), await generateStubCert()];
        const message = new StubMessage(
          recipientPrivateAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
          { senderCaCertificateChain: chain },
        );

        expect(message.senderCaCertificateChain).toEqual(chain);
      });

      test('Sender certificate should be excluded from chain if included', async () => {
        const chain: readonly Certificate[] = [await generateStubCert()];
        const message = new StubMessage(
          recipientPrivateAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
          {
            senderCaCertificateChain: [...chain, senderCertificate],
          },
        );

        expect(message.senderCaCertificateChain).toEqual(chain);
      });
    });
  });

  test('getSenderCertificationPath should return certification path', async () => {
    const message = new StubMessage(
      await stubSenderChain.recipientCert.calculateSubjectPrivateAddress(),
      stubSenderChain.senderCert,
      STUB_PAYLOAD_PLAINTEXT,
      {
        senderCaCertificateChain: [stubSenderChain.recipientCert],
      },
    );

    await expect(message.getSenderCertificationPath([stubSenderChain.rootCert])).resolves.toEqual([
      stubSenderChain.senderCert,
      stubSenderChain.recipientCert,
      stubSenderChain.rootCert,
    ]);
  });

  test('expiryDate field should calculate expiry date from creation date and TTL', () => {
    const message = new StubMessage(
      'some-address',
      stubSenderChain.senderCert,
      STUB_PAYLOAD_PLAINTEXT,
      {
        creationDate: new Date('2020-04-07T21:00:00Z'),
        ttl: 5,
      },
    );

    const expectedExpiryDate = new Date(message.creationDate.getTime());
    expectedExpiryDate.setSeconds(expectedExpiryDate.getSeconds() + message.ttl);
    expect(message.expiryDate).toEqual(expectedExpiryDate);
  });

  describe('validate', () => {
    describe('Authorization', () => {
      test('Message should be refused if sender is not trusted', async () => {
        const message = new StubMessage(
          await stubSenderChain.recipientCert.calculateSubjectPrivateAddress(),
          reSerializeCertificate(senderCertificate),
          STUB_PAYLOAD_PLAINTEXT,
        );

        jestDateMock.advanceBy(1_000);

        await expect(message.validate([stubSenderChain.rootCert])).rejects.toEqual(
          new InvalidMessageError('Sender is not authorized: No valid certificate paths found'),
        );
      });

      test('Message should be accepted if sender is trusted', async () => {
        const message = new StubMessage(
          await stubSenderChain.recipientCert.calculateSubjectPrivateAddress(),
          stubSenderChain.senderCert,
          STUB_PAYLOAD_PLAINTEXT,
          {
            senderCaCertificateChain: [stubSenderChain.recipientCert],
          },
        );

        jestDateMock.advanceBy(1_000);

        await expect(message.validate([stubSenderChain.rootCert])).toResolve();
      });

      test('Message should be refused if recipient is private and did not authorize', async () => {
        const message = new StubMessage(
          '0deadbeef',
          stubSenderChain.senderCert,
          STUB_PAYLOAD_PLAINTEXT,
          {
            senderCaCertificateChain: [stubSenderChain.recipientCert],
          },
        );

        jestDateMock.advanceBy(1_000);

        await expect(message.validate([stubSenderChain.rootCert])).rejects.toEqual(
          new InvalidMessageError(`Sender is not authorized to reach ${message.recipientAddress}`),
        );
      });

      test('Message should be accepted if recipient address is public', async () => {
        const message = new StubMessage(
          'https://example.com',
          stubSenderChain.senderCert,
          STUB_PAYLOAD_PLAINTEXT,
          {
            senderCaCertificateChain: [stubSenderChain.recipientCert],
          },
        );

        jestDateMock.advanceBy(1_000);

        await expect(message.validate([stubSenderChain.rootCert])).toResolve();
      });

      test('Authorization enforcement should be skipped if trusted certs are absent', async () => {
        const message = new StubMessage('0deadbeef', senderCertificate, STUB_PAYLOAD_PLAINTEXT);

        jestDateMock.advanceBy(1_000);

        await expect(message.validate()).toResolve();
      });
    });

    describe('Validity period', () => {
      const recipientPublicAddress = 'https://example.com';

      test('Date equal to the current date should be accepted', async () => {
        const stubDate = new Date(
          senderCertificate.pkijsCertificate.notAfter.value.getTime() - 1_000,
        );
        stubDate.setSeconds(0, 0);
        const message = new StubMessage(
          recipientPublicAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
          { creationDate: stubDate },
        );
        jestDateMock.advanceTo(stubDate);

        await message.validate();
      });

      test('Date should not be in the future', async () => {
        const message = new StubMessage(
          recipientPublicAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
        );
        message.creationDate.setMilliseconds(0);

        const oneSecondAgo = new Date(message.creationDate);
        oneSecondAgo.setDate(oneSecondAgo.getDate() - 1_000);
        jestDateMock.advanceTo(oneSecondAgo);

        await expect(message.validate()).rejects.toEqual(
          new InvalidMessageError('Message date is in the future'),
        );
      });

      test('Date should not be before start date of sender certificate', async () => {
        const certStartDate = senderCertificate.pkijsCertificate.notBefore.value;
        const message = new StubMessage(
          recipientPublicAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
          { creationDate: new Date(certStartDate.getTime() - 1_000) },
        );

        jestDateMock.advanceTo(certStartDate);
        await expect(message.validate()).rejects.toEqual(
          new InvalidMessageError('Message was created before the sender certificate was valid'),
        );
      });

      test('Date may be at the expiry date of sender certificate', async () => {
        const certEndDate = senderCertificate.pkijsCertificate.notAfter.value;
        const message = new StubMessage(
          recipientPublicAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
          { creationDate: certEndDate },
        );

        jestDateMock.advanceTo(message.creationDate);

        await message.validate();
      });

      test('Date should not be after expiry date of sender certificate', async () => {
        const certEndDate = senderCertificate.pkijsCertificate.notAfter.value;
        const message = new StubMessage(
          recipientPublicAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
          { creationDate: new Date(certEndDate.getTime() + 1_000) },
        );

        jestDateMock.advanceTo(message.creationDate);
        await expect(message.validate()).rejects.toEqual(
          new InvalidMessageError('Message was created after the sender certificate expired'),
        );
      });

      test('TTL matching current time should be accepted', async () => {
        const message = new StubMessage(
          recipientPublicAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
          {
            creationDate: senderCertificate.pkijsCertificate.notBefore.value,
            ttl: 1,
          },
        );

        const currentDate = new Date(message.creationDate);
        currentDate.setSeconds(currentDate.getSeconds() + message.ttl);
        currentDate.setMilliseconds(1); // Should be greater than zero so we can test rounding too
        jestDateMock.advanceTo(currentDate);

        await message.validate();
      });

      test('TTL in the past should not be accepted', async () => {
        const message = new StubMessage(
          recipientPublicAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
          { ttl: 1 },
        );

        jestDateMock.advanceTo(message.creationDate.getTime() + (message.ttl + 1) * 1_000);
        await expect(message.validate()).rejects.toEqual(
          new InvalidMessageError('Message already expired'),
        );
      });
    });
  });

  describe('unwrapPayload', () => {
    test('SessionlessEnvelopedData payload should be decrypted', async () => {
      const envelopedData = await SessionlessEnvelopedData.encrypt(
        STUB_PAYLOAD_PLAINTEXT,
        recipientCertificate,
      );

      const recipientKeyStore = new MockPrivateKeyStore();
      await recipientKeyStore.registerNodeKey(recipientPrivateKey, recipientCertificate);

      const stubMessage = new StubMessage(
        '0123',
        senderCertificate,
        Buffer.from(envelopedData.serialize()),
      );

      const { payload, senderSessionKey } = await stubMessage.unwrapPayload(recipientKeyStore);

      expect(payload).toBeInstanceOf(StubPayload);
      expect(payload.content).toEqual(bufferToArray(STUB_PAYLOAD_PLAINTEXT));

      expect(senderSessionKey).toBeUndefined();
    });

    test('SessionEnvelopedData payload should be decrypted', async () => {
      const recipientDhKeyPair = await generateECDHKeyPair();
      const tomorrow = new Date();
      tomorrow.setDate(tomorrow.getDate() + 1);
      const recipientDhCertificate = await issueInitialDHKeyCertificate({
        issuerCertificate: recipientCertificate,
        issuerPrivateKey: recipientPrivateKey,
        subjectPublicKey: recipientDhKeyPair.publicKey,
        validityEndDate: tomorrow,
      });
      const { envelopedData } = await SessionEnvelopedData.encrypt(
        STUB_PAYLOAD_PLAINTEXT,
        recipientDhCertificate,
      );

      const recipientKeyStore = new MockPrivateKeyStore();
      await recipientKeyStore.registerInitialSessionKey(
        recipientDhKeyPair.privateKey,
        recipientDhCertificate,
      );

      const stubMessage = new StubMessage(
        '0123',
        senderCertificate,
        Buffer.from(envelopedData.serialize()),
      );

      const { payload, senderSessionKey } = await stubMessage.unwrapPayload(recipientKeyStore);

      expect(payload).toBeInstanceOf(StubPayload);
      expect(payload.content).toEqual(bufferToArray(STUB_PAYLOAD_PLAINTEXT));

      expect(senderSessionKey).toEqual(await envelopedData.getOriginatorKey());
    });

    test('Keystore lookup should be skipped if private key is provided', async () => {
      const envelopedData = await SessionlessEnvelopedData.encrypt(
        STUB_PAYLOAD_PLAINTEXT,
        recipientCertificate,
      );

      const stubMessage = new StubMessage(
        '0123',
        senderCertificate,
        Buffer.from(envelopedData.serialize()),
      );

      const { payload } = await stubMessage.unwrapPayload(recipientPrivateKey);

      expect(payload).toBeInstanceOf(StubPayload);
      expect(payload.content).toEqual(bufferToArray(STUB_PAYLOAD_PLAINTEXT));
    });
  });

  describe('isRecipientAddressPrivate', () => {
    test('True should be returned when address is private', () => {
      const message = new StubMessage(
        recipientPrivateAddress,
        senderCertificate,
        STUB_PAYLOAD_PLAINTEXT,
      );

      expect(message.isRecipientAddressPrivate).toBeTrue();
    });

    test('False should be returned when address is public', () => {
      const message = new StubMessage(
        'https://example.com',
        senderCertificate,
        STUB_PAYLOAD_PLAINTEXT,
      );

      expect(message.isRecipientAddressPrivate).toBeFalse();
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
