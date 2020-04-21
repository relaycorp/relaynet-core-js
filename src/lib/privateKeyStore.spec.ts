// tslint:disable:no-let
import { expectPromiseToReject, generateStubCert, sha256Hex } from './_test_utils';
import * as keys from './crypto_wrappers/keys';
import Certificate from './crypto_wrappers/x509/Certificate';
import {
  BoundPrivateKeyData,
  PrivateKeyData,
  PrivateKeyStore,
  PrivateKeyStoreError,
  UnboundPrivateKeyData,
} from './privateKeyStore';

// TODO: Replace base64 with hex encoding

class MockPrivateKeyStore extends PrivateKeyStore {
  // tslint:disable-next-line:readonly-keyword
  public readonly keys: { [key: string]: PrivateKeyData } = {};

  constructor(protected readonly failOnSave = false) {
    super();
  }

  // TODO: REMOVE
  public registerStubKey(keyId: Buffer, privateKeyData: PrivateKeyData): void {
    // tslint:disable-next-line:no-object-mutation
    this.keys[keyId.toString('base64')] = privateKeyData;
  }

  public async registerNodeKey(privateKey: CryptoKey, certificate: Certificate): Promise<void> {
    // tslint:disable-next-line:no-object-mutation
    this.keys[certificate.getSerialNumberHex()] = {
      certificateDer: Buffer.from(certificate.serialize()),
      keyDer: await keys.derSerializePrivateKey(privateKey),
      type: 'node',
    } as UnboundPrivateKeyData;
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
    } as UnboundPrivateKeyData;
  }

  public async registerSubsequentSessionKey(
    privateKey: CryptoKey,
    certificate: Certificate,
  ): Promise<void> {
    // tslint:disable-next-line:no-object-mutation
    this.keys[certificate.getSerialNumberHex()] = {
      keyDer: await keys.derSerializePrivateKey(privateKey),
      recipientPublicKeyDigest: await sha256Hex(await certificate.getPublicKey()),
      type: 'session',
    } as BoundPrivateKeyData;
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
  const stubKeyId = Buffer.from([1, 3, 5, 7, 9]); // TODO: DELETE
  const stubKeyIdBase64 = stubKeyId.toString('base64'); // TODO: DELETE
  const KEY_ID_HEX = 'abcdef012';
  let stubPrivateKey: CryptoKey;
  let stubCertificate: Certificate;

  const stubPrivateKeyDer = Buffer.from('DER-encoded private key');
  const mockDerSerialize = jest.spyOn(keys, 'derSerializePrivateKey');
  beforeEach(() => {
    mockDerSerialize.mockReset();
    mockDerSerialize.mockResolvedValueOnce(stubPrivateKeyDer);
  });
  afterAll(() => {
    mockDerSerialize.mockRestore();
  });

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

        const keyPair = await store.fetchNodeKey(stubCertificate.getSerialNumberHex());

        expect(keyPair).toHaveProperty('privateKey', stubPrivateKey);

        expect(stubCertificate.isEqual(keyPair.certificate)).toBeTrue();
      });

      test('Session keys should not be returned', async () => {
        const store = new MockPrivateKeyStore();
        await store.registerInitialSessionKey(stubPrivateKey, stubCertificate);

        await expectPromiseToReject(
          store.fetchNodeKey(stubCertificate.getSerialNumberHex()),
          new PrivateKeyStoreError(`Key ${stubCertificate.getSerialNumberHex()} is not a node key`),
        );
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore();

        await expectPromiseToReject(
          store.fetchNodeKey(stubCertificate.getSerialNumberHex()),
          new PrivateKeyStoreError(`Failed to retrieve key: Unknown key ${stubKeyIdBase64}`),
        );
      });
    });

    describe('saveNodeKey', () => {
      test('Key should be stored', async () => {
        const store = new MockPrivateKeyStore();

        await store.saveNodeKey(stubPrivateKey, stubCertificate);

        expect(store.keys).toHaveProperty(stubCertificate.getSerialNumberHex());
        const keyDatum = store.keys[stubCertificate.getSerialNumberHex()];
        expect(keyDatum).toHaveProperty('keyDer', stubPrivateKeyDer);
        expect(keyDatum).toHaveProperty('certificateDer', Buffer.from(stubCertificate.serialize()));
        expect(keyDatum).toHaveProperty('type', 'node');
        expect(keyDatum).not.toHaveProperty('recipientPublicKeyDigest');
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

      stubCertificate = await generateStubCert();
    });

    let stubRecipientCertificate: Certificate;
    beforeAll(async () => {
      const recipientKeyPair = await keys.generateRSAKeyPair();
      stubRecipientCertificate = await generateStubCert({
        issuerPrivateKey: recipientKeyPair.privateKey,
        subjectPublicKey: recipientKeyPair.publicKey,
      });
    });

    const mockDerDeserialize = jest.spyOn(keys, 'derDeserializeECDHPrivateKey');
    beforeEach(() => {
      mockDerDeserialize.mockResolvedValueOnce(stubPrivateKey);
    });
    afterAll(() => {
      mockDerDeserialize.mockRestore();
    });

    // TODO: REMOVE
    const stubInitialSessionKeyData: UnboundPrivateKeyData = {
      certificateDer: Buffer.from('cert'),
      keyDer: Buffer.from('private key'),
      type: 'session-initial' as const,
    };
    let stubSubsequentSessionKeyData: BoundPrivateKeyData;
    beforeAll(async () => {
      // TODO: REMOVE
      stubSubsequentSessionKeyData = {
        ...stubInitialSessionKeyData,
        recipientPublicKeyDigest: await keys.getPublicKeyDigestHex(
          await stubRecipientCertificate.getPublicKey(),
        ),
        type: 'session',
      };
    });

    describe('fetchSessionKey', () => {
      test('Existing, unbound key should be returned', async () => {
        const store = new MockPrivateKeyStore();
        store.registerStubKey(stubKeyId, stubInitialSessionKeyData);

        const privateKeyData = await store.fetchSessionKey(stubKeyId, stubRecipientCertificate);

        expect(privateKeyData).toBe(stubPrivateKey);

        expect(mockDerDeserialize).toBeCalledTimes(1);
        expect(mockDerDeserialize).toBeCalledWith(stubInitialSessionKeyData.keyDer, 'P-256');
      });

      test('Existing, bound key should be returned', async () => {
        const store = new MockPrivateKeyStore();
        store.registerStubKey(stubKeyId, stubSubsequentSessionKeyData);

        const privateKeyData = await store.fetchSessionKey(stubKeyId, stubRecipientCertificate);

        expect(privateKeyData).toBe(stubPrivateKey);
      });

      test('Key ids should be base64-encoded', async () => {
        const store = new MockPrivateKeyStore();
        store.registerStubKey(stubKeyId, stubSubsequentSessionKeyData);

        const privateKeyData = await store.fetchSessionKey(stubKeyId, stubRecipientCertificate);

        expect(privateKeyData).toBe(stubPrivateKey);
      });

      test('Keys bound to another recipient should not be returned', async () => {
        const store = new MockPrivateKeyStore();
        store.registerStubKey(stubKeyId, {
          ...stubSubsequentSessionKeyData,
          recipientPublicKeyDigest: `not ${stubSubsequentSessionKeyData.recipientPublicKeyDigest}`,
        });

        await expectPromiseToReject(
          store.fetchSessionKey(stubKeyId, stubRecipientCertificate),
          new PrivateKeyStoreError(`Key ${stubKeyId} is bound to another recipient`),
        );
      });

      test('Node keys should not be returned', async () => {
        const store = new MockPrivateKeyStore();
        await store.registerNodeKey(stubPrivateKey, stubCertificate);

        await expectPromiseToReject(
          store.fetchSessionKey(stubKeyId, stubRecipientCertificate),
          new PrivateKeyStoreError(`Key ${stubKeyId} is not a session key`),
        );
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore();

        await expectPromiseToReject(
          store.fetchSessionKey(stubKeyId, stubRecipientCertificate),
          new PrivateKeyStoreError(`Failed to retrieve key: Unknown key ${stubKeyIdBase64}`),
        );
      });
    });

    describe('saveSessionKey', () => {
      test('Unbound key should be stored', async () => {
        const store = new MockPrivateKeyStore();

        await store.saveSessionKey(stubPrivateKey, stubKeyId);

        expect(store.keys).toHaveProperty(stubKeyIdBase64);
        expect(store.keys[stubKeyIdBase64]).toHaveProperty('keyDer', stubPrivateKeyDer);
        expect(store.keys[stubKeyIdBase64]).toHaveProperty('type', 'session');
        expect(store.keys[stubKeyIdBase64]).toHaveProperty('recipientPublicKeyDigest', undefined);
      });

      test('Bound key should be stored', async () => {
        const store = new MockPrivateKeyStore();

        await store.saveSessionKey(stubPrivateKey, stubKeyId, stubRecipientCertificate);

        expect(store.keys).toHaveProperty(stubKeyIdBase64);
        expect(store.keys[stubKeyIdBase64]).toHaveProperty('keyDer', stubPrivateKeyDer);
        expect(store.keys[stubKeyIdBase64]).toHaveProperty('type', 'session');
        expect(store.keys[stubKeyIdBase64]).toHaveProperty(
          'recipientPublicKeyDigest',
          await keys.getPublicKeyDigestHex(await stubRecipientCertificate.getPublicKey()),
        );
      });

      test('Key ids should be base64-encoded', async () => {
        const store = new MockPrivateKeyStore();

        await store.saveSessionKey(stubPrivateKey, stubKeyId, stubRecipientCertificate);

        expect(store.keys).toHaveProperty(stubKeyIdBase64);
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore(true);

        await expectPromiseToReject(
          store.saveSessionKey(stubPrivateKey, stubKeyId),
          new PrivateKeyStoreError(`Failed to save key: Denied`),
        );
      });
    });
  });
});
