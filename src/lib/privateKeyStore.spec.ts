// tslint:disable:no-let

import { expectPromiseToReject, generateStubCert } from './_test_utils';
import * as keys from './crypto_wrappers/keys';
import Certificate from './crypto_wrappers/x509/Certificate';
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
  let stubPrivateKey: CryptoKey;
  let stubCertificate: Certificate;

  describe('Node keys', () => {
    beforeAll(async () => {
      const keyPair = await keys.generateRSAKeyPair();
      stubPrivateKey = keyPair.privateKey;

      stubCertificate = await generateStubCert();
    });

    describe('fetchNodeKey', () => {
      test('Existing key pair should be returned', async () => {
        const store = new MockPrivateKeyStore();
        await store.registerNodeKey(stubPrivateKey, stubCertificate);

        const keyPair = await store.fetchNodeKey(stubCertificate.getSerialNumber());

        expect(keyPair).toHaveProperty('privateKey', stubPrivateKey);
        expect(stubCertificate.isEqual(keyPair.certificate)).toBeTrue();
      });

      test('Session keys should not be returned', async () => {
        const store = new MockPrivateKeyStore();
        await store.registerInitialSessionKey(stubPrivateKey, stubCertificate);

        await expectPromiseToReject(
          store.fetchNodeKey(stubCertificate.getSerialNumber()),
          new PrivateKeyStoreError('Key is not a node key'),
        );
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore();

        await expectPromiseToReject(
          store.fetchNodeKey(stubCertificate.getSerialNumber()),
          new PrivateKeyStoreError(
            `Failed to retrieve key: Unknown key ${stubCertificate.getSerialNumberHex()}`,
          ),
        );
      });
    });

    describe('saveNodeKey', () => {
      test('Key should be stored', async () => {
        const store = new MockPrivateKeyStore();

        await store.saveNodeKey(stubPrivateKey, stubCertificate);

        const expectedKey: UnboundPrivateKeyData = {
          certificateDer: Buffer.from(stubCertificate.serialize()),
          keyDer: await keys.derSerializePrivateKey(stubPrivateKey),
          type: 'node',
        };
        expect(store.keys[stubCertificate.getSerialNumberHex()]).toEqual(expectedKey);
      });

      test('Key ids should be hex-encoded', async () => {
        const store = new MockPrivateKeyStore();

        await store.saveNodeKey(stubPrivateKey, stubCertificate);

        expect(store.keys).toHaveProperty(stubCertificate.getSerialNumberHex());
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore(true);

        await expectPromiseToReject(
          store.saveNodeKey(stubPrivateKey, stubCertificate),
          new PrivateKeyStoreError(`Failed to save key: Denied`),
        );
      });
    });
  });

  describe('Session keys', () => {
    beforeAll(async () => {
      const keyPair = await keys.generateECDHKeyPair();
      stubPrivateKey = keyPair.privateKey;

      stubCertificate = await generateStubCert(); // TODO: MOVE INTO INITIAL SESSION KEYS
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
          await store.registerInitialSessionKey(stubPrivateKey, stubCertificate);

          const keyPair = await store.fetchInitialSessionKey(stubCertificate.getSerialNumber());

          expect(await keys.derSerializePrivateKey(keyPair.privateKey)).toEqual(
            await keys.derSerializePrivateKey(stubPrivateKey),
          );
          expect(stubCertificate.isEqual(keyPair.certificate)).toBeTrue();
        });

        test('Node keys should not be returned', async () => {
          const store = new MockPrivateKeyStore();
          await store.registerNodeKey(stubPrivateKey, stubCertificate);

          await expect(
            store.fetchInitialSessionKey(stubCertificate.getSerialNumber()),
          ).rejects.toEqual(new PrivateKeyStoreError('Key is not an initial session key'));
        });

        test('Subsequent session keys should not be returned', async () => {
          const store = new MockPrivateKeyStore();
          await store.registerSubsequentSessionKey(
            stubPrivateKey,
            stubCertificate.getSerialNumberHex(),
            await generateStubCert(),
          );

          await expect(
            store.fetchInitialSessionKey(stubCertificate.getSerialNumber()),
          ).rejects.toEqual(new PrivateKeyStoreError('Key is not an initial session key'));
        });

        test('Errors should be wrapped', async () => {
          const store = new MockPrivateKeyStore();

          await expectPromiseToReject(
            store.fetchInitialSessionKey(stubCertificate.getSerialNumber()),
            new PrivateKeyStoreError(
              `Failed to retrieve key: Unknown key ${stubCertificate.getSerialNumberHex()}`,
            ),
          );
        });
      });

      describe('saveInitialSessionKey', () => {
        test('Unbound key should be stored', async () => {
          const store = new MockPrivateKeyStore();

          await store.saveInitialSessionKey(stubPrivateKey, stubCertificate);

          const expectedKey: UnboundPrivateKeyData = {
            certificateDer: Buffer.from(await stubCertificate.serialize()),
            keyDer: await keys.derSerializePrivateKey(stubPrivateKey),
            type: 'session-initial',
          };
          expect(store.keys[stubCertificate.getSerialNumberHex()]).toEqual(expectedKey);
        });

        test('Errors should be wrapped', async () => {
          const store = new MockPrivateKeyStore(true);

          await expectPromiseToReject(
            store.saveInitialSessionKey(stubPrivateKey, stubCertificate),
            new PrivateKeyStoreError(`Failed to save key: Denied`),
          );
        });
      });
    });

    describe('fetchSessionKey', () => {
      test('Initial session keys should be returned', async () => {
        const store = new MockPrivateKeyStore();
        await store.registerInitialSessionKey(stubPrivateKey, stubCertificate);

        const privateKeyData = await store.fetchSessionKey(
          stubCertificate.getSerialNumber(),
          stubRecipientCertificate,
        );

        expect(await keys.derSerializePrivateKey(privateKeyData)).toEqual(
          await keys.derSerializePrivateKey(stubPrivateKey),
        );
      });

      test('Subsequent session keys should be returned', async () => {
        const store = new MockPrivateKeyStore();
        await store.registerSubsequentSessionKey(
          stubPrivateKey,
          stubCertificate.getSerialNumberHex(),
          stubRecipientCertificate,
        );

        const privateKeyData = await store.fetchSessionKey(
          stubCertificate.getSerialNumber(),
          stubRecipientCertificate,
        );

        expect(await keys.derSerializePrivateKey(privateKeyData)).toEqual(
          await keys.derSerializePrivateKey(stubPrivateKey),
        );
      });

      test('Keys bound to another recipient should not be returned', async () => {
        const store = new MockPrivateKeyStore();
        await store.registerSubsequentSessionKey(
          stubPrivateKey,
          stubCertificate.getSerialNumberHex(),
          stubRecipientCertificate,
        );

        const differentRecipientCert = await generateStubCert();
        await expectPromiseToReject(
          store.fetchSessionKey(stubCertificate.getSerialNumber(), differentRecipientCert),
          new PrivateKeyStoreError('Key is bound to another recipient'),
        );
      });

      test('Node keys should not be returned', async () => {
        const store = new MockPrivateKeyStore();
        await store.registerNodeKey(stubPrivateKey, stubCertificate);

        await expect(
          store.fetchSessionKey(stubCertificate.getSerialNumber(), stubRecipientCertificate),
        ).rejects.toEqual(new PrivateKeyStoreError('Key is not a session key'));
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore();

        await expectPromiseToReject(
          store.fetchSessionKey(stubCertificate.getSerialNumber(), stubRecipientCertificate),
          new PrivateKeyStoreError(
            `Failed to retrieve key: Unknown key ${stubCertificate.getSerialNumberHex()}`,
          ),
        );
      });
    });

    describe('Subsequent session keys', () => {
      describe('saveSubsequentSessionKey', () => {
        test('Bound key should be stored', async () => {
          const store = new MockPrivateKeyStore();

          await store.saveSubsequentSessionKey(
            stubPrivateKey,
            stubCertificate.getSerialNumber(),
            stubRecipientCertificate,
          );

          const expectedKey: BoundPrivateKeyData = {
            keyDer: await keys.derSerializePrivateKey(stubPrivateKey),
            recipientPublicKeyDigest: await keys.getPublicKeyDigestHex(
              await stubRecipientCertificate.getPublicKey(),
            ),
            type: 'session-subsequent',
          };
          expect(store.keys[stubCertificate.getSerialNumberHex()]).toEqual(expectedKey);
        });

        test('Errors should be wrapped', async () => {
          const store = new MockPrivateKeyStore(true);

          await expectPromiseToReject(
            store.saveSubsequentSessionKey(
              stubPrivateKey,
              stubCertificate.getSerialNumber(),
              stubRecipientCertificate,
            ),
            new PrivateKeyStoreError(`Failed to save key: Denied`),
          );
        });
      });
    });
  });
});
