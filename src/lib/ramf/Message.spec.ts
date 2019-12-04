/* tslint:disable:no-let max-classes-per-file */
import bufferToArray from 'buffer-to-arraybuffer';
import * as jestDateMock from 'jest-date-mock';

import { generateStubCert } from '../_test_utils';
import { generateRsaKeys } from '../crypto';
import Certificate from '../pki/Certificate';
import { StubMessage } from './_test_utils';

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
  jestDateMock.clear();
});

describe('Message', () => {
  let recipientAddress: string;
  let recipientCertificate: Certificate;
  let senderCertificate: Certificate;
  beforeAll(async () => {
    const recipientKeyPair = await generateRsaKeys();
    recipientCertificate = await generateStubCert({
      subjectPublicKey: recipientKeyPair.publicKey
    });
    recipientAddress = recipientCertificate.getAddress();

    const senderKeyPair = await generateRsaKeys();
    senderCertificate = await generateStubCert({
      subjectPublicKey: senderKeyPair.publicKey
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
        expect(message.date.getTimezoneOffset()).toEqual(0);
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

    describe('Payload', () => {
      test('Payload should be imported when present', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload);

        expect(message.payloadPlaintext).toBe(payload);
      });

      test('Payload import should be skipped when it is absent', async () => {
        const message = new StubMessage(recipientAddress, senderCertificate);

        expect(message.payloadPlaintext).toBe(undefined);
      });
    });

    describe('Sender certificate chain', () => {
      test('Sender certificate chain should only contain sender certificate by default', () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload);

        expect(message.senderCertificateChain).toEqual(new Set([senderCertificate]));
      });

      test('A custom sender certificate chain should be accepted', async () => {
        const chain = new Set([await generateStubCert(), senderCertificate]);
        const message = new StubMessage(recipientAddress, senderCertificate, payload, {
          senderCertificateChain: chain
        });

        expect(message.senderCertificateChain).toEqual(chain);
      });

      test('Sender certificate should be added to custom chain if missing', async () => {
        const additionalCertificate = await generateStubCert();
        const message = new StubMessage(recipientAddress, senderCertificate, payload, {
          senderCertificateChain: new Set([additionalCertificate])
        });

        expect(message.senderCertificateChain).toEqual(
          new Set([senderCertificate, additionalCertificate])
        );
      });
    });
  });
});
