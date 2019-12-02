/* tslint:disable:no-let max-classes-per-file */
import bufferToArray from 'buffer-to-arraybuffer';
import * as jestDateMock from 'jest-date-mock';

import { generateStubCert } from '../_test_utils';
import { generateRsaKeys } from '../crypto';
import Certificate from '../pki/Certificate';
import { StubMessage } from './_test_utils';
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
    describe('Address', () => {
      test('An address with a length of up to 10 bits should be accepted', () => {
        const address = 'a'.repeat(2 ** 10 - 1);
        const message = new StubMessage(address, senderCertificate, payload);

        expect(message.recipientAddress).toEqual(address);
      });

      test('An address with a length greater than 10 bites should be refused', () => {
        const invalidAddress = 'a'.repeat(2 ** 10);
        expect(
          () => new StubMessage(invalidAddress, senderCertificate, payload)
        ).toThrowWithMessage(RAMFError, 'Recipient address exceeds maximum length');
      });

      test('Multi-byte characters should be accounted for in length validation', () => {
        const invalidAddress = '❤'.repeat(2 ** 10 - 1);
        expect(
          () => new StubMessage(invalidAddress, senderCertificate, payload)
        ).toThrowWithMessage(RAMFError, 'Recipient address exceeds maximum length');
      });
    });

    describe('Id', () => {
      test('Random ids should be assigned by default', () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload);

        expect(message.id).toEqual(mockStubUuid4);
      });

      test('A custom id with a length of up to 8 bits should be accepted', () => {
        const customId = 'a'.repeat(2 ** 8 - 1);
        const message = new StubMessage(recipientAddress, senderCertificate, payload, {
          id: customId
        });
        expect(message.id).toEqual(customId);
      });

      test('A custom id with a length greater than 8 bits should be refused', () => {
        const invalidId = 'a'.repeat(2 ** 8);
        expect(
          () =>
            new StubMessage(recipientAddress, senderCertificate, payload, {
              id: invalidId
            })
        ).toThrowWithMessage(RAMFError, 'Custom id exceeds maximum length');
      });
    });

    describe('Date', () => {
      test('The current date should be used by default', () => {
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

      test('A custom date should not be before Unix epoch', () => {
        const invalidDate = new Date(1969, 11, 31, 23, 59, 59);

        expect(
          () =>
            new StubMessage(recipientAddress, senderCertificate, payload, {
              date: invalidDate
            })
        ).toThrowWithMessage(RAMFError, 'Date cannot be before Unix epoch');
      });

      test('The timestamp of a custom date should be less than 2 ^ 32', () => {
        const invalidDate = new Date(2 ** 32 * 1000);

        expect(
          () =>
            new StubMessage(recipientAddress, senderCertificate, payload, {
              date: invalidDate
            })
        ).toThrowWithMessage(RAMFError, 'Date timestamp cannot be represented with 32 bits');
      });

      test('A custom date should be stored in UTC', () => {
        const date = new Date('01 Jan 2019 12:00:00 GMT+11:00');

        const message = new StubMessage(recipientAddress, senderCertificate, payload, { date });

        expect(message.date).toEqual(new Date('01 Jan 2019 01:00:00 GMT'));
      });
    });

    describe('TTL', () => {
      test('5 minutes should be the default TTL', () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload);

        expect(message.ttl).toEqual(5 * 60);
      });

      test('A custom TTL under 2^24 should be accepted', () => {
        const ttl = 2 ** 24 - 1;
        const message = new StubMessage(recipientAddress, senderCertificate, payload, { ttl });

        expect(message.ttl).toEqual(ttl);
      });

      test('A custom TTL of zero should be accepted', () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload, { ttl: 0 });

        expect(message.ttl).toEqual(0);
      });

      test('A custom TTL should not be negative', () => {
        expect(
          () =>
            new StubMessage(recipientAddress, senderCertificate, payload, {
              ttl: -1
            })
        ).toThrowWithMessage(RAMFError, 'TTL cannot be negative');
      });

      test('A custom TTL should be less than 2 ^ 24', () => {
        expect(
          () =>
            new StubMessage(recipientAddress, senderCertificate, payload, {
              ttl: 2 ** 24
            })
        ).toThrowWithMessage(RAMFError, 'TTL must be less than 2^24');
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
      test('Sender certificate chain should be empty by default', () => {
        const message = new StubMessage(recipientAddress, senderCertificate, payload);

        expect(message.senderCertificateChain).toHaveProperty('size', 0);
      });

      test('A custom sender certificate chain should be accepted', async () => {
        const chain = new Set([await generateStubCert()]);
        const message = new StubMessage(recipientAddress, senderCertificate, payload, {
          senderCertificateChain: chain
        });

        expect(message.senderCertificateChain).toEqual(chain);
      });
    });
  });
});
