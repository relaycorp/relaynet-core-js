// tslint:disable:no-let

import { expectPromiseToReject, generateStubCert } from '../_test_utils';
import * as keys from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import {
  BoundPrivateKeyData,
  PrivateKeyData,
  PrivateKeyStore,
  PrivateKeyStoreError,
  UnboundPrivateKeyData,
} from './privateKeyStore';

class MockPrivateKeyStore extends PrivateKeyStore {
  // tslint:disable-next-line:readonly-keyword
  public readonly keys: { [key: string]: PrivateKeyData } = {};

  constructor(protected readonly failOnSave = false) {
    super();
  }

  public async registerNodeKey(privateKey: CryptoKey, certificate: Certificate): Promise<void> {
    // tslint:disable-next-line:no-object-mutation
    this.keys[certificate.getSerialNumberHex()] = {
      certificateDer: Buffer.from(certificate.serialize()),
      keyDer: await keys.derSerializePrivateKey(privateKey),
      type: 'node',
    };
  }

  public async registerInitialSessionKey(
    privateKey: CryptoKey,
    certificate: Certificate,
  ): Promise<void> {
    // tslint:disable-next-line:no-object-mutation
    this.keys[certificate.getSerialNumberHex()] = {
      certificateDer: Buffer.from(certificate.serialize()),
      keyDer: await keys.derSerializePrivateKey(privateKey),
      type: 'session-initial',
    };
  }

  public async registerSubsequentSessionKey(
    privateKey: CryptoKey,
    keyId: string,
    recipientCertificate: Certificate,
  ): Promise<void> {
    // tslint:disable-next-line:no-object-mutation
    this.keys[keyId] = {
      keyDer: await keys.derSerializePrivateKey(privateKey),
      recipientPublicKeyDigest: await keys.getPublicKeyDigestHex(
        await recipientCertificate.getPublicKey(),
      ),
      type: 'session-subsequent',
    };
  }

  protected async fetchKey(keyId: string): Promise<PrivateKeyData> {
    if (keyId in this.keys) {
      return this.keys[keyId];
    }
    throw new Error(`Unknown key ${keyId}`);
  }

  protected async saveKey(privateKeyData: PrivateKeyData, keyId: string): Promise<void> {
    if (this.failOnSave) {
      throw new Error('Denied');
    }
    // tslint:disable-next-line:no-object-mutation
    this.keys[keyId] = privateKeyData;
  }
}

describe('PrivateKeyStore', () => {
  let PRIVATE_KEY: CryptoKey;
  let CERTIFICATE: Certificate;

  describe('Node keys', () => {
    beforeAll(async () => {
      const keyPair = await keys.generateRSAKeyPair();
      PRIVATE_KEY = keyPair.privateKey;

      CERTIFICATE = await generateStubCert();
    });

    describe('fetchNodeKey', () => {
      test('Existing key pair should be returned', async () => {
        const store = new MockPrivateKeyStore();
        await store.registerNodeKey(PRIVATE_KEY, CERTIFICATE);

        const keyPair = await store.fetchNodeKey(CERTIFICATE.getSerialNumber());

        expect(keyPair).toHaveProperty('privateKey', PRIVATE_KEY);
        expect(CERTIFICATE.isEqual(keyPair.certificate)).toBeTrue();
      });

      test('Session keys should not be returned', async () => {
        const store = new MockPrivateKeyStore();
        await store.registerInitialSessionKey(PRIVATE_KEY, CERTIFICATE);

        await expectPromiseToReject(
          store.fetchNodeKey(CERTIFICATE.getSerialNumber()),
          new PrivateKeyStoreError('Key is not a node key'),
        );
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore();

        await expectPromiseToReject(
          store.fetchNodeKey(CERTIFICATE.getSerialNumber()),
          new PrivateKeyStoreError(
            `Failed to retrieve key: Unknown key ${CERTIFICATE.getSerialNumberHex()}`,
          ),
        );
      });
    });

    describe('saveNodeKey', () => {
      test('Key should be stored', async () => {
        const store = new MockPrivateKeyStore();

        await store.saveNodeKey(PRIVATE_KEY, CERTIFICATE);

        const expectedKey: UnboundPrivateKeyData = {
          certificateDer: Buffer.from(CERTIFICATE.serialize()),
          keyDer: await keys.derSerializePrivateKey(PRIVATE_KEY),
          type: 'node',
        };
        expect(store.keys[CERTIFICATE.getSerialNumberHex()]).toEqual(expectedKey);
      });

      test('Key ids should be hex-encoded', async () => {
        const store = new MockPrivateKeyStore();

        await store.saveNodeKey(PRIVATE_KEY, CERTIFICATE);

        expect(store.keys).toHaveProperty(CERTIFICATE.getSerialNumberHex());
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore(true);

        await expectPromiseToReject(
          store.saveNodeKey(PRIVATE_KEY, CERTIFICATE),
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
          const store = new MockPrivateKeyStore();
          await store.registerInitialSessionKey(PRIVATE_KEY, CERTIFICATE);

          const keyPair = await store.fetchInitialSessionKey(CERTIFICATE.getSerialNumber());

          expect(await keys.derSerializePrivateKey(keyPair.privateKey)).toEqual(
            await keys.derSerializePrivateKey(PRIVATE_KEY),
          );
          expect(CERTIFICATE.isEqual(keyPair.certificate)).toBeTrue();
        });

        test('Node keys should not be returned', async () => {
          const store = new MockPrivateKeyStore();
          await store.registerNodeKey(PRIVATE_KEY, CERTIFICATE);

          await expect(store.fetchInitialSessionKey(CERTIFICATE.getSerialNumber())).rejects.toEqual(
            new PrivateKeyStoreError('Key is not an initial session key'),
          );
        });

        test('Subsequent session keys should not be returned', async () => {
          const store = new MockPrivateKeyStore();
          await store.registerSubsequentSessionKey(
            PRIVATE_KEY,
            CERTIFICATE.getSerialNumberHex(),
            await generateStubCert(),
          );

          await expect(store.fetchInitialSessionKey(CERTIFICATE.getSerialNumber())).rejects.toEqual(
            new PrivateKeyStoreError('Key is not an initial session key'),
          );
        });

        test('Errors should be wrapped', async () => {
          const store = new MockPrivateKeyStore();

          await expectPromiseToReject(
            store.fetchInitialSessionKey(CERTIFICATE.getSerialNumber()),
            new PrivateKeyStoreError(
              `Failed to retrieve key: Unknown key ${CERTIFICATE.getSerialNumberHex()}`,
            ),
          );
        });
      });

      describe('saveInitialSessionKey', () => {
        test('Unbound key should be stored', async () => {
          const store = new MockPrivateKeyStore();

          await store.saveInitialSessionKey(PRIVATE_KEY, CERTIFICATE);

          const expectedKey: UnboundPrivateKeyData = {
            certificateDer: Buffer.from(await CERTIFICATE.serialize()),
            keyDer: await keys.derSerializePrivateKey(PRIVATE_KEY),
            type: 'session-initial',
          };
          expect(store.keys[CERTIFICATE.getSerialNumberHex()]).toEqual(expectedKey);
        });

        test('Errors should be wrapped', async () => {
          const store = new MockPrivateKeyStore(true);

          await expectPromiseToReject(
            store.saveInitialSessionKey(PRIVATE_KEY, CERTIFICATE),
            new PrivateKeyStoreError(`Failed to save key: Denied`),
          );
        });
      });
    });

    describe('fetchSessionKey', () => {
      test('Initial session keys should be returned', async () => {
        const store = new MockPrivateKeyStore();
        await store.registerInitialSessionKey(PRIVATE_KEY, CERTIFICATE);

        const privateKeyData = await store.fetchSessionKey(
          CERTIFICATE.getSerialNumber(),
          stubRecipientCertificate,
        );

        expect(await keys.derSerializePrivateKey(privateKeyData)).toEqual(
          await keys.derSerializePrivateKey(PRIVATE_KEY),
        );
      });

      test('Subsequent session keys should be returned', async () => {
        const store = new MockPrivateKeyStore();
        await store.registerSubsequentSessionKey(
          PRIVATE_KEY,
          CERTIFICATE.getSerialNumberHex(),
          stubRecipientCertificate,
        );

        const privateKeyData = await store.fetchSessionKey(
          CERTIFICATE.getSerialNumber(),
          stubRecipientCertificate,
        );

        expect(await keys.derSerializePrivateKey(privateKeyData)).toEqual(
          await keys.derSerializePrivateKey(PRIVATE_KEY),
        );
      });

      test('Keys bound to another recipient should not be returned', async () => {
        const store = new MockPrivateKeyStore();
        await store.registerSubsequentSessionKey(
          PRIVATE_KEY,
          CERTIFICATE.getSerialNumberHex(),
          stubRecipientCertificate,
        );

        const differentRecipientCert = await generateStubCert();
        await expectPromiseToReject(
          store.fetchSessionKey(CERTIFICATE.getSerialNumber(), differentRecipientCert),
          new PrivateKeyStoreError('Key is bound to another recipient'),
        );
      });

      test('Node keys should not be returned', async () => {
        const store = new MockPrivateKeyStore();
        await store.registerNodeKey(PRIVATE_KEY, CERTIFICATE);

        await expect(
          store.fetchSessionKey(CERTIFICATE.getSerialNumber(), stubRecipientCertificate),
        ).rejects.toEqual(new PrivateKeyStoreError('Key is not a session key'));
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore();

        await expectPromiseToReject(
          store.fetchSessionKey(CERTIFICATE.getSerialNumber(), stubRecipientCertificate),
          new PrivateKeyStoreError(
            `Failed to retrieve key: Unknown key ${CERTIFICATE.getSerialNumberHex()}`,
          ),
        );
      });
    });

    describe('Subsequent session keys', () => {
      describe('saveSubsequentSessionKey', () => {
        test('Bound key should be stored', async () => {
          const store = new MockPrivateKeyStore();

          await store.saveSubsequentSessionKey(
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
          expect(store.keys[CERTIFICATE.getSerialNumberHex()]).toEqual(expectedKey);
        });

        test('Errors should be wrapped', async () => {
          const store = new MockPrivateKeyStore(true);

          await expectPromiseToReject(
            store.saveSubsequentSessionKey(
              PRIVATE_KEY,
              CERTIFICATE.getSerialNumber(),
              stubRecipientCertificate,
            ),
            new PrivateKeyStoreError(`Failed to save key: Denied`),
          );
        });
      });
    });
  });
});
