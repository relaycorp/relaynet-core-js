/* tslint:disable:no-let max-classes-per-file */
import * as jestDateMock from 'jest-date-mock';

import { expectPromiseToReject, generateStubCert, reSerializeCertificate } from '../_test_utils';
import { generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { StubMessage } from './_test_utils';
import InvalidMessageError from './InvalidMessageError';

const mockStubUuid4 = '56e95d8a-6be2-4020-bb36-5dd0da36c181';
jest.mock('uuid4', () => {
  return {
    __esModule: true,
    default: jest.fn().mockImplementation(() => mockStubUuid4),
  };
});

const payload = Buffer.from('Hi');

afterEach(() => {
  jest.restoreAllMocks();
  jestDateMock.clear();
});

describe('Message', () => {
  let recipientAddress: string;
  let recipientCertificate: Certificate;
  let senderCertificate: Certificate;
  beforeAll(async () => {
    const recipientKeyPair = await generateRSAKeyPair();
    recipientCertificate = await generateStubCert({
      subjectPublicKey: recipientKeyPair.publicKey,
    });
    recipientAddress = recipientCertificate.getCommonName();

    const senderKeyPair = await generateRSAKeyPair();
    senderCertificate = await generateStubCert({
      subjectPublicKey: senderKeyPair.publicKey,
    });
  });

  describe('constructor', () => {
    describe('Id', () => {
      test('Id should fall back to UUID4 when left unspecified', () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload);

        expect(message.id).toEqual(mockStubUuid4);
      });
    });

    describe('Date', () => {
      test('The current date (UTC) should be used by default', () => {
        const now = new Date(2019, 1, 1, 1, 1, 1, 1);
        jestDateMock.advanceTo(now);

        const message = new StubMessage(recipientAddress, senderCertificate, payload);

        expect(message.date).toEqual(now);
      });

      test('A custom date should be accepted', () => {
        const date = new Date(2020, 1, 1, 1, 1, 1, 1);

        const message = new StubMessage(recipientAddress, senderCertificate, payload, { date });

        expect(message.date).toEqual(date);
      });
    });

    describe('TTL', () => {
      test('TTL should be 5 minutes by default', () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload);

        expect(message.ttl).toEqual(5 * 60);
      });

      test('A custom TTL under 2^24 should be accepted', () => {
        const ttl = 2 ** 24 - 1;
        const message = new StubMessage(recipientAddress, senderCertificate, payload, { ttl });

        expect(message.ttl).toEqual(ttl);
      });
    });

    describe('Sender CA certificate chain', () => {
      test('CA certificate chain should be empty by default', () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload);

        expect(message.senderCaCertificateChain).toEqual([]);
      });

      test('A custom sender certificate chain should be accepted', async () => {
        const chain: readonly Certificate[] = [await generateStubCert(), senderCertificate];
        const message = new StubMessage(recipientAddress, senderCertificate, payload, {
          senderCaCertificateChain: chain,
        });

        expect(message.senderCaCertificateChain).toEqual(chain);
      });
    });
  });

  describe('validate', () => {
    let stubRootCaCert: Certificate;
    let stubRecipient: Certificate;
    let stubAuthorizedSender: Certificate;
    beforeAll(async () => {
      const trustedCaKeyPair = await generateRSAKeyPair();
      stubRootCaCert = reSerializeCertificate(
        await generateStubCert({
          attributes: { isCA: true, serialNumber: 1 },
          issuerPrivateKey: trustedCaKeyPair.privateKey,
          subjectPublicKey: trustedCaKeyPair.publicKey,
        }),
      );

      const recipientKeyPair = await generateRSAKeyPair();
      stubRecipient = reSerializeCertificate(
        await generateStubCert({
          attributes: { isCA: true, serialNumber: 2 },
          issuerCertificate: stubRootCaCert,
          issuerPrivateKey: trustedCaKeyPair.privateKey,
          subjectPublicKey: recipientKeyPair.publicKey,
        }),
      );

      stubAuthorizedSender = reSerializeCertificate(
        await generateStubCert({
          attributes: { isCA: false, serialNumber: 3 },
          issuerCertificate: stubRecipient,
          issuerPrivateKey: recipientKeyPair.privateKey,
        }),
      );
    });

    describe('Authorization', () => {
      test('Parcel should be refused if sender is not trusted', async () => {
        const message = new StubMessage(
          await stubRecipient.calculateSubjectPrivateAddress(),
          reSerializeCertificate(senderCertificate),
          payload,
        );

        await expectPromiseToReject(
          message.validate([stubRootCaCert]),
          new InvalidMessageError('Sender is not authorized: No valid certificate paths found'),
        );
      });

      test('Parcel should be accepted if sender is trusted', async () => {
        const message = new StubMessage(
          await stubRecipient.calculateSubjectPrivateAddress(),
          stubAuthorizedSender,
          payload,
          {
            senderCaCertificateChain: [stubRecipient],
          },
        );

        await expect(message.validate([stubRootCaCert])).toResolve();
      });

      test('Parcel should be refused if recipient is not issuer of sender', async () => {
        const message = new StubMessage('0deadbeef', stubAuthorizedSender, payload, {
          senderCaCertificateChain: [stubRecipient],
        });

        await expectPromiseToReject(
          message.validate([stubRootCaCert]),
          new InvalidMessageError(`Sender is not authorized to reach ${message.recipientAddress}`),
        );
      });

      test('Authorization enforcement should be skipped if trusted certs are absent', async () => {
        const message = new StubMessage('0deadbeef', senderCertificate, payload);

        await expect(message.validate()).toResolve();
      });
    });
  });
});
