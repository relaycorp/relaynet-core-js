// tslint:disable:no-let

import { generateStubCert } from '../_test_utils';
import * as keys from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import {
  BoundPrivateKeyData,
  PrivateKeyStoreError,
  UnboundPrivateKeyData,
} from './privateKeyStore';
import { MockPrivateKeyStore } from './testMocks';
import UnknownKeyError from './UnknownKeyError';

describe('PrivateKeyStore', () => {
  let PRIVATE_KEY: CryptoKey;
  let CERTIFICATE: Certificate;

  const MOCK_STORE = new MockPrivateKeyStore();
  beforeEach(() => {
    MOCK_STORE.clear();
  });

  describe('Node keys', () => {
    beforeAll(async () => {
      const keyPair = await keys.generateRSAKeyPair();
      PRIVATE_KEY = keyPair.privateKey;

      CERTIFICATE = await generateStubCert();
    });

    describe('fetchNodeKey', () => {
      test('Existing key pair should be returned', async () => {
        await MOCK_STORE.registerNodeKey(PRIVATE_KEY, CERTIFICATE);

        const keyPair = await MOCK_STORE.fetchNodeKey(CERTIFICATE.getSerialNumber());

        expect(keyPair).toHaveProperty('privateKey', PRIVATE_KEY);
        expect(CERTIFICATE.isEqual(keyPair.certificate)).toBeTrue();
      });

      test('UnknownKeyError should be thrown if key pair does not exist', async () => {
        await expect(MOCK_STORE.fetchNodeKey(CERTIFICATE.getSerialNumber())).rejects.toBeInstanceOf(
          UnknownKeyError,
        );
      });

      test('Session keys should not be returned', async () => {
        await MOCK_STORE.registerInitialSessionKey(PRIVATE_KEY, CERTIFICATE);

        await expect(MOCK_STORE.fetchNodeKey(CERTIFICATE.getSerialNumber())).rejects.toBeInstanceOf(
          UnknownKeyError,
        );
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore(false, true);

        await expect(store.fetchNodeKey(CERTIFICATE.getSerialNumber())).rejects.toEqual(
          new PrivateKeyStoreError('Failed to retrieve key: Denied'),
        );
      });
    });

    describe('saveNodeKey', () => {
      test('Key should be stored', async () => {
        await MOCK_STORE.saveNodeKey(PRIVATE_KEY, CERTIFICATE);

        const expectedKey: UnboundPrivateKeyData = {
          certificateDer: Buffer.from(CERTIFICATE.serialize()),
          keyDer: await keys.derSerializePrivateKey(PRIVATE_KEY),
          type: 'node',
        };
        expect(MOCK_STORE.keys[CERTIFICATE.getSerialNumberHex()]).toEqual(expectedKey);
      });

      test('Key ids should be hex-encoded', async () => {
        await MOCK_STORE.saveNodeKey(PRIVATE_KEY, CERTIFICATE);

        expect(MOCK_STORE.keys).toHaveProperty(CERTIFICATE.getSerialNumberHex());
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore(true);

        await expect(store.saveNodeKey(PRIVATE_KEY, CERTIFICATE)).rejects.toEqual(
          new PrivateKeyStoreError(`Failed to save key: Denied`),
        );
      });
    });
  });

  describe('Session keys', () => {
    beforeAll(async () => {
      const keyPair = await keys.generateECDHKeyPair();
      PRIVATE_KEY = keyPair.privateKey;

      CERTIFICATE = await generateStubCert();
    });

    let stubRecipientCertificate: Certificate;
    beforeAll(async () => {
      const recipientKeyPair = await keys.generateRSAKeyPair();
      stubRecipientCertificate = await generateStubCert({
        issuerPrivateKey: recipientKeyPair.privateKey,
        subjectPublicKey: recipientKeyPair.publicKey,
      });
    });

    describe('Initial session keys', () => {
      describe('fetchInitialSessionKey', () => {
        test('Existing key pair should be returned', async () => {
          await MOCK_STORE.registerInitialSessionKey(PRIVATE_KEY, CERTIFICATE);

          const keyPair = await MOCK_STORE.fetchInitialSessionKey(CERTIFICATE.getSerialNumber());

          expect(await keys.derSerializePrivateKey(keyPair.privateKey)).toEqual(
            await keys.derSerializePrivateKey(PRIVATE_KEY),
          );
          expect(CERTIFICATE.isEqual(keyPair.certificate)).toBeTrue();
        });

        test('UnknownKeyError should be thrown if key pair does not exist', async () => {
          await expect(
            MOCK_STORE.fetchInitialSessionKey(CERTIFICATE.getSerialNumber()),
          ).rejects.toBeInstanceOf(UnknownKeyError);
        });

        test('Node keys should not be returned', async () => {
          await MOCK_STORE.registerNodeKey(PRIVATE_KEY, CERTIFICATE);

          await expect(
            MOCK_STORE.fetchInitialSessionKey(CERTIFICATE.getSerialNumber()),
          ).rejects.toBeInstanceOf(UnknownKeyError);
        });

        test('Subsequent session keys should not be returned', async () => {
          await MOCK_STORE.registerSubsequentSessionKey(
            PRIVATE_KEY,
            CERTIFICATE.getSerialNumberHex(),
            await generateStubCert(),
          );

          await expect(
            MOCK_STORE.fetchInitialSessionKey(CERTIFICATE.getSerialNumber()),
          ).rejects.toBeInstanceOf(UnknownKeyError);
        });

        test('Errors should be wrapped', async () => {
          const store = new MockPrivateKeyStore(false, true);

          await expect(store.fetchInitialSessionKey(CERTIFICATE.getSerialNumber())).rejects.toEqual(
            new PrivateKeyStoreError('Failed to retrieve key: Denied'),
          );
        });
      });

      describe('saveInitialSessionKey', () => {
        test('Unbound key should be stored', async () => {
          await MOCK_STORE.saveInitialSessionKey(PRIVATE_KEY, CERTIFICATE);

          const expectedKey: UnboundPrivateKeyData = {
            certificateDer: Buffer.from(await CERTIFICATE.serialize()),
            keyDer: await keys.derSerializePrivateKey(PRIVATE_KEY),
            type: 'session-initial',
          };
          expect(MOCK_STORE.keys[CERTIFICATE.getSerialNumberHex()]).toEqual(expectedKey);
        });

        test('Errors should be wrapped', async () => {
          const store = new MockPrivateKeyStore(true);

          await expect(store.saveInitialSessionKey(PRIVATE_KEY, CERTIFICATE)).rejects.toEqual(
            new PrivateKeyStoreError(`Failed to save key: Denied`),
          );
        });
      });
    });

    describe('fetchSessionKey', () => {
      test('Initial session keys should be returned', async () => {
        await MOCK_STORE.registerInitialSessionKey(PRIVATE_KEY, CERTIFICATE);

        const privateKey = await MOCK_STORE.fetchSessionKey(
          CERTIFICATE.getSerialNumber(),
          stubRecipientCertificate,
        );

        expect(await keys.derSerializePrivateKey(privateKey)).toEqual(
          await keys.derSerializePrivateKey(PRIVATE_KEY),
        );
      });

      test('Subsequent session keys should be returned', async () => {
        await MOCK_STORE.registerSubsequentSessionKey(
          PRIVATE_KEY,
          CERTIFICATE.getSerialNumberHex(),
          stubRecipientCertificate,
        );

        const privateKey = await MOCK_STORE.fetchSessionKey(
          CERTIFICATE.getSerialNumber(),
          stubRecipientCertificate,
        );

        expect(await keys.derSerializePrivateKey(privateKey)).toEqual(
          await keys.derSerializePrivateKey(PRIVATE_KEY),
        );
      });

      test('UnknownKeyError should be thrown if key pair does not exist', async () => {
        await expect(
          MOCK_STORE.fetchSessionKey(CERTIFICATE.getSerialNumber(), stubRecipientCertificate),
        ).rejects.toBeInstanceOf(UnknownKeyError);
      });

      test('Keys bound to another recipient should not be returned', async () => {
        await MOCK_STORE.registerSubsequentSessionKey(
          PRIVATE_KEY,
          CERTIFICATE.getSerialNumberHex(),
          stubRecipientCertificate,
        );

        const differentRecipientCert = await generateStubCert();
        await expect(
          MOCK_STORE.fetchSessionKey(CERTIFICATE.getSerialNumber(), differentRecipientCert),
        ).rejects.toBeInstanceOf(UnknownKeyError);
      });

      test('Node keys should not be returned', async () => {
        await MOCK_STORE.registerNodeKey(PRIVATE_KEY, CERTIFICATE);

        await expect(
          MOCK_STORE.fetchSessionKey(CERTIFICATE.getSerialNumber(), stubRecipientCertificate),
        ).rejects.toBeInstanceOf(UnknownKeyError);
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore(false, true);

        await expect(
          store.fetchSessionKey(CERTIFICATE.getSerialNumber(), stubRecipientCertificate),
        ).rejects.toEqual(new PrivateKeyStoreError('Failed to retrieve key: Denied'));
      });
    });

    describe('saveSubsequentSessionKey', () => {
      test('Bound key should be stored', async () => {
        await MOCK_STORE.saveSubsequentSessionKey(
          PRIVATE_KEY,
          CERTIFICATE.getSerialNumber(),
          stubRecipientCertificate,
        );

        const expectedKey: BoundPrivateKeyData = {
          keyDer: await keys.derSerializePrivateKey(PRIVATE_KEY),
          recipientPublicKeyDigest: await keys.getPublicKeyDigestHex(
            await stubRecipientCertificate.getPublicKey(),
          ),
          type: 'session-subsequent',
        };
        expect(MOCK_STORE.keys[CERTIFICATE.getSerialNumberHex()]).toEqual(expectedKey);
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore(true);

        await expect(
          store.saveSubsequentSessionKey(
            PRIVATE_KEY,
            CERTIFICATE.getSerialNumber(),
            stubRecipientCertificate,
          ),
        ).rejects.toEqual(new PrivateKeyStoreError(`Failed to save key: Denied`));
      });
    });
  });
});
