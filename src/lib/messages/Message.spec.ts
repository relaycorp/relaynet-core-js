/* tslint:disable:no-let max-classes-per-file */
import bufferToArray from 'buffer-to-arraybuffer';
import * as jestDateMock from 'jest-date-mock';

import {
  castMock,
  expectPromiseToReject,
  generateStubCert,
  reSerializeCertificate,
} from '../_test_utils';
import {
  SessionEnvelopedData,
  SessionlessEnvelopedData,
} from '../crypto_wrappers/cms/envelopedData';
import { generateECDHKeyPair, generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { PrivateKeyStore } from '../keyStores/privateKeyStore';
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

describe('Message', () => {
  let recipientAddress: string;
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
    recipientAddress = recipientCertificate.getCommonName();

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
          recipientAddress,
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
          recipientAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
        );

        expect(message.date).toEqual(now);
      });

      test('A custom date should be accepted', () => {
        const date = new Date(2020, 1, 1, 1, 1, 1, 1);

        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
          { date },
        );

        expect(message.date).toEqual(date);
      });
    });

    describe('TTL', () => {
      test('TTL should be 5 minutes by default', () => {
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
        );

        expect(message.ttl).toEqual(5 * 60);
      });

      test('A custom TTL under 2^24 should be accepted', () => {
        const ttl = 2 ** 24 - 1;
        const message = new StubMessage(
          recipientAddress,
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
          recipientAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
        );

        expect(message.senderCaCertificateChain).toEqual([]);
      });

      test('A custom sender certificate chain should be accepted', async () => {
        const chain: readonly Certificate[] = [await generateStubCert(), senderCertificate];
        const message = new StubMessage(
          recipientAddress,
          senderCertificate,
          STUB_PAYLOAD_PLAINTEXT,
          {
            senderCaCertificateChain: chain,
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
        date: new Date('2020-04-07T21:00:00Z'),
        ttl: 5,
      },
    );

    const expectedExpiryDate = new Date(message.date.getTime());
    expectedExpiryDate.setSeconds(expectedExpiryDate.getSeconds() + message.ttl);
    expect(message.expiryDate).toEqual(expectedExpiryDate);
  });

  describe('validate', () => {
    describe('Authorization', () => {
      test('Parcel should be refused if sender is not trusted', async () => {
        const message = new StubMessage(
          await stubSenderChain.recipientCert.calculateSubjectPrivateAddress(),
          reSerializeCertificate(senderCertificate),
          STUB_PAYLOAD_PLAINTEXT,
        );

        await expectPromiseToReject(
          message.validate([stubSenderChain.rootCert]),
          new InvalidMessageError('Sender is not authorized: No valid certificate paths found'),
        );
      });

      test('Parcel should be accepted if sender is trusted', async () => {
        const message = new StubMessage(
          await stubSenderChain.recipientCert.calculateSubjectPrivateAddress(),
          stubSenderChain.senderCert,
          STUB_PAYLOAD_PLAINTEXT,
          {
            senderCaCertificateChain: [stubSenderChain.recipientCert],
          },
        );

        await expect(message.validate([stubSenderChain.rootCert])).toResolve();
      });

      test('Parcel should be refused if recipient is not issuer of sender', async () => {
        const message = new StubMessage(
          '0deadbeef',
          stubSenderChain.senderCert,
          STUB_PAYLOAD_PLAINTEXT,
          {
            senderCaCertificateChain: [stubSenderChain.recipientCert],
          },
        );

        await expectPromiseToReject(
          message.validate([stubSenderChain.rootCert]),
          new InvalidMessageError(`Sender is not authorized to reach ${message.recipientAddress}`),
        );
      });

      test('Authorization enforcement should be skipped if trusted certs are absent', async () => {
        const message = new StubMessage('0deadbeef', senderCertificate, STUB_PAYLOAD_PLAINTEXT);

        await expect(message.validate()).toResolve();
      });
    });
  });

  describe('unwrapPayload', () => {
    test('SessionlessEnvelopedData payload should be decrypted', async () => {
      const envelopedData = await SessionlessEnvelopedData.encrypt(
        STUB_PAYLOAD_PLAINTEXT,
        recipientCertificate,
      );

      const keyStore = castMock<PrivateKeyStore>({
        fetchNodeKey: jest
          .fn()
          .mockResolvedValue({ certificate: senderCertificate, privateKey: recipientPrivateKey }),
      });

      const stubMessage = new StubMessage(
        '0123',
        senderCertificate,
        Buffer.from(envelopedData.serialize()),
      );

      const { payload, senderSessionKey } = await stubMessage.unwrapPayload(keyStore);

      expect(payload).toBeInstanceOf(StubPayload);
      expect(payload.content).toEqual(bufferToArray(STUB_PAYLOAD_PLAINTEXT));
      expect(keyStore.fetchNodeKey).toBeCalledWith(recipientCertificate.getSerialNumber());

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

      const keyStore = castMock<PrivateKeyStore>({
        fetchSessionKey: jest.fn().mockResolvedValue(recipientDhKeyPair.privateKey),
      });

      const stubMessage = new StubMessage(
        '0123',
        senderCertificate,
        Buffer.from(envelopedData.serialize()),
      );

      const { payload, senderSessionKey } = await stubMessage.unwrapPayload(keyStore);

      expect(payload).toBeInstanceOf(StubPayload);
      expect(payload.content).toEqual(bufferToArray(STUB_PAYLOAD_PLAINTEXT));
      expect(keyStore.fetchSessionKey).toBeCalledWith(
        recipientDhCertificate.getSerialNumber(),
        senderCertificate,
      );

      expect(senderSessionKey).toEqual(await envelopedData.getOriginatorKey());
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
