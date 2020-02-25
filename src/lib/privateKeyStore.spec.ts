// tslint:disable:no-let no-object-mutation
import { expectPromiseToReject } from './_test_utils';
import * as keys from './crypto_wrappers/keys';
import { PrivateKeyData, PrivateKeyStore, PrivateKeyStoreError } from './privateKeyStore';

class StubPrivateKeyStore extends PrivateKeyStore {
  // tslint:disable-next-line:readonly-keyword
  public readonly keys: { [key: string]: PrivateKeyData } = {};

  constructor(protected readonly failOnSave = false) {
    super();
  }

  public registerStubKey(keyId: Buffer, privateKeyData: PrivateKeyData): void {
    this.keys[keyId.toString('base64')] = privateKeyData;
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
    this.keys[keyId] = privateKeyData;
  }
}

describe('PrivateKeyStore', () => {
  const stubKeyId = Buffer.from([1, 3, 5, 7, 9]);
  const stubKeyIdBase64 = stubKeyId.toString('base64');
  let stubPrivateKey: CryptoKey;

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
    });

    const stubPrivateKeyData = {
      keyDer: Buffer.from('private key'),
      recipientPublicKeyDigest: 'digest',
      type: 'node' as const,
    };

    describe('fetchNodeKey', () => {
      const mockDerDeserialize = jest.spyOn(keys, 'derDeserializeRSAPrivateKey');
      beforeEach(() => {
        mockDerDeserialize.mockResolvedValueOnce(stubPrivateKey);
      });
      afterAll(() => {
        mockDerDeserialize.mockRestore();
      });

      test('Existing key should be returned', async () => {
        const store = new StubPrivateKeyStore();
        store.registerStubKey(stubKeyId, stubPrivateKeyData);

        const privateKeyData = await store.fetchNodeKey(stubKeyId);

        expect(privateKeyData).toBe(stubPrivateKey);

        expect(mockDerDeserialize).toBeCalledTimes(1);
        expect(mockDerDeserialize).toBeCalledWith(stubPrivateKeyData.keyDer, {
          hash: { name: 'SHA-256' },
          name: 'RSA-PSS',
        });
      });

      test('Key ids should be base64-encoded', async () => {
        const store = new StubPrivateKeyStore();
        store.registerStubKey(stubKeyId, stubPrivateKeyData);

        const privateKeyData = await store.fetchNodeKey(stubKeyId);

        expect(privateKeyData).toBe(stubPrivateKey);
      });

      test('Session keys should not be returned', async () => {
        const store = new StubPrivateKeyStore();
        store.registerStubKey(stubKeyId, { ...stubPrivateKeyData, type: 'session' as const });

        await expectPromiseToReject(
          store.fetchNodeKey(stubKeyId),
          new PrivateKeyStoreError(`Key ${stubKeyId} is not a node key`),
        );
      });

      test('Errors should be wrapped', async () => {
        const store = new StubPrivateKeyStore();

        await expectPromiseToReject(
          store.fetchNodeKey(stubKeyId),
          new PrivateKeyStoreError(`Failed to retrieve key: Unknown key ${stubKeyIdBase64}`),
        );
      });
    });

    describe('saveNodeKey', () => {
      test('Key should be stored', async () => {
        const store = new StubPrivateKeyStore();

        await store.saveNodeKey(stubPrivateKey, stubKeyId);

        expect(store.keys).toHaveProperty(stubKeyIdBase64);
        const keyDatum = store.keys[stubKeyIdBase64];
        expect(keyDatum).toHaveProperty('keyDer', stubPrivateKeyDer);
        expect(keyDatum).toHaveProperty('type', 'node');
        expect(keyDatum).not.toHaveProperty('recipientPublicKeyDigest');
      });

      test('Key ids should be base64-encoded', async () => {
        const store = new StubPrivateKeyStore();

        await store.saveNodeKey(stubPrivateKey, stubKeyId);

        expect(store.keys).toHaveProperty(stubKeyIdBase64);
      });

      test('Errors should be wrapped', async () => {
        const store = new StubPrivateKeyStore(true);

        await expectPromiseToReject(
          store.saveNodeKey(stubPrivateKey, stubKeyId),
          new PrivateKeyStoreError(`Failed to save key: Denied`),
        );
      });
    });
  });

  describe('Session keys', () => {
    beforeAll(async () => {
      const keyPair = await keys.generateECDHKeyPair();
      stubPrivateKey = keyPair.privateKey;
    });

    let stubRecipientPublicKey: CryptoKey;
    beforeAll(async () => {
      const recipientKeyPair = await keys.generateRSAKeyPair();
      stubRecipientPublicKey = recipientKeyPair.publicKey;
    });

    const mockDerDeserialize = jest.spyOn(keys, 'derDeserializeECDHPrivateKey');
    beforeEach(() => {
      mockDerDeserialize.mockResolvedValueOnce(stubPrivateKey);
    });
    afterAll(() => {
      mockDerDeserialize.mockRestore();
    });

    const stubUnboundPrivateKeyData: PrivateKeyData = {
      keyDer: Buffer.from('private key'),
      type: 'session' as const,
    };
    let stubBoundPrivateKeyData: PrivateKeyData;
    beforeAll(async () => {
      stubBoundPrivateKeyData = {
        ...stubUnboundPrivateKeyData,
        recipientPublicKeyDigest: await keys.getPublicKeyDigestHex(stubRecipientPublicKey),
      };
    });

    describe('fetchSessionKey', () => {
      test('Existing, unbound key should be returned', async () => {
        const store = new StubPrivateKeyStore();
        store.registerStubKey(stubKeyId, stubUnboundPrivateKeyData);

        const privateKeyData = await store.fetchSessionKey(stubKeyId, stubRecipientPublicKey);

        expect(privateKeyData).toBe(stubPrivateKey);

        expect(mockDerDeserialize).toBeCalledTimes(1);
        expect(mockDerDeserialize).toBeCalledWith(stubUnboundPrivateKeyData.keyDer, 'P-256');
      });

      test('Existing, bound key should be returned', async () => {
        const store = new StubPrivateKeyStore();
        store.registerStubKey(stubKeyId, stubBoundPrivateKeyData);

        const privateKeyData = await store.fetchSessionKey(stubKeyId, stubRecipientPublicKey);

        expect(privateKeyData).toBe(stubPrivateKey);
      });

      test('Key ids should be base64-encoded', async () => {
        const store = new StubPrivateKeyStore();
        store.registerStubKey(stubKeyId, stubBoundPrivateKeyData);

        const privateKeyData = await store.fetchSessionKey(stubKeyId, stubRecipientPublicKey);

        expect(privateKeyData).toBe(stubPrivateKey);
      });

      test('Keys bound to another recipient should not be returned', async () => {
        const store = new StubPrivateKeyStore();
        store.registerStubKey(stubKeyId, {
          ...stubBoundPrivateKeyData,
          recipientPublicKeyDigest: `not ${stubBoundPrivateKeyData.recipientPublicKeyDigest}`,
        });

        await expectPromiseToReject(
          store.fetchSessionKey(stubKeyId, stubRecipientPublicKey),
          new PrivateKeyStoreError(`Key ${stubKeyId} is bound to another recipient`),
        );
      });

      test('Node keys should not be returned', async () => {
        const store = new StubPrivateKeyStore();
        store.registerStubKey(stubKeyId, { ...stubBoundPrivateKeyData, type: 'node' as const });

        await expectPromiseToReject(
          store.fetchSessionKey(stubKeyId, stubRecipientPublicKey),
          new PrivateKeyStoreError(`Key ${stubKeyId} is not a session key`),
        );
      });

      test('Errors should be wrapped', async () => {
        const store = new StubPrivateKeyStore();

        await expectPromiseToReject(
          store.fetchSessionKey(stubKeyId, stubRecipientPublicKey),
          new PrivateKeyStoreError(`Failed to retrieve key: Unknown key ${stubKeyIdBase64}`),
        );
      });
    });

    describe('saveSessionKey', () => {
      test('Unbound key should be stored', async () => {
        const store = new StubPrivateKeyStore();

        await store.saveSessionKey(stubPrivateKey, stubKeyId);

        expect(store.keys).toHaveProperty(stubKeyIdBase64);
        expect(store.keys[stubKeyIdBase64]).toHaveProperty('keyDer', stubPrivateKeyDer);
        expect(store.keys[stubKeyIdBase64]).toHaveProperty('type', 'session');
        expect(store.keys[stubKeyIdBase64]).toHaveProperty('recipientPublicKeyDigest', undefined);
      });

      test('Bound key should be stored', async () => {
        const store = new StubPrivateKeyStore();

        await store.saveSessionKey(stubPrivateKey, stubKeyId, stubRecipientPublicKey);

        expect(store.keys).toHaveProperty(stubKeyIdBase64);
        expect(store.keys[stubKeyIdBase64]).toHaveProperty('keyDer', stubPrivateKeyDer);
        expect(store.keys[stubKeyIdBase64]).toHaveProperty('type', 'session');
        expect(store.keys[stubKeyIdBase64]).toHaveProperty(
          'recipientPublicKeyDigest',
          await keys.getPublicKeyDigestHex(stubRecipientPublicKey),
        );
      });

      test('Key ids should be base64-encoded', async () => {
        const store = new StubPrivateKeyStore();

        await store.saveSessionKey(stubPrivateKey, stubKeyId, stubRecipientPublicKey);

        expect(store.keys).toHaveProperty(stubKeyIdBase64);
      });

      test('Errors should be wrapped', async () => {
        const store = new StubPrivateKeyStore(true);

        await expectPromiseToReject(
          store.saveSessionKey(stubPrivateKey, stubKeyId),
          new PrivateKeyStoreError(`Failed to save key: Denied`),
        );
      });
    });
  });
});
