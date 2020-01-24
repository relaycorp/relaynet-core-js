// tslint:disable:no-let no-object-mutation
import { expectPromiseToReject } from './_test_utils';
import * as keys from './crypto_wrappers/keys';
import { PrivateKeyData, PrivateKeyStore, PrivateKeyStoreError } from './privateKeyStore';

class StubPrivateKeyStore extends PrivateKeyStore {
  // tslint:disable-next-line:readonly-keyword
  public readonly keys: { [key: string]: PrivateKeyData } = {};

  protected async fetchKey(keyId: string): Promise<PrivateKeyData> {
    if (keyId in this.keys) {
      return this.keys[keyId];
    }
    throw new Error(`Unknown key ${keyId}`);
  }
}

describe('PrivateKeyStore', () => {
  const stubKeyId = '123';
  let stubPrivateKey: CryptoKey;

  describe('Node keys', () => {
    beforeAll(async () => {
      const keyPair = await keys.generateRSAKeyPair();
      stubPrivateKey = keyPair.privateKey;
    });

    const mockDerDeserialize = jest.spyOn(keys, 'derDeserializeRSAPrivateKey');
    beforeEach(() => {
      mockDerDeserialize.mockResolvedValueOnce(stubPrivateKey);
    });
    afterAll(() => {
      mockDerDeserialize.mockRestore();
    });

    describe('fetchNodeKey', () => {
      const stubPrivateKeyData = {
        keyDer: Buffer.from('private key'),
        recipientPublicKeyDigest: 'digest',
        type: 'node' as const,
      };

      test('Existing key should be returned', async () => {
        const store = new StubPrivateKeyStore();
        store.keys[stubKeyId] = stubPrivateKeyData;

        const privateKeyData = await store.fetchNodeKey(stubKeyId);

        expect(privateKeyData).toBe(stubPrivateKey);

        expect(mockDerDeserialize).toBeCalledTimes(1);
        expect(mockDerDeserialize).toBeCalledWith(stubPrivateKeyData.keyDer, {
          hash: { name: 'SHA-256' },
          name: 'RSA-PSS',
        });
      });

      test('Session keys should not be returned', async () => {
        const store = new StubPrivateKeyStore();
        store.keys[stubKeyId] = { ...stubPrivateKeyData, type: 'session' as const };

        await expectPromiseToReject(
          store.fetchNodeKey(stubKeyId),
          new PrivateKeyStoreError(`Key ${stubKeyId} is not a node key`),
        );
      });

      test('Errors should be wrapped', async () => {
        const store = new StubPrivateKeyStore();

        await expectPromiseToReject(
          store.fetchSessionKey(stubKeyId),
          new PrivateKeyStoreError(
            `Failed to retrieve session key ${stubKeyId}: Unknown key ${stubKeyId}`,
          ),
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
        store.keys[stubKeyId] = stubUnboundPrivateKeyData;

        const privateKeyData = await store.fetchSessionKey(stubKeyId);

        expect(privateKeyData).toBe(stubPrivateKey);

        expect(mockDerDeserialize).toBeCalledTimes(1);
        expect(mockDerDeserialize).toBeCalledWith(stubUnboundPrivateKeyData.keyDer, 'P-256');
      });

      test('Existing, bound key should be returned', async () => {
        const store = new StubPrivateKeyStore();
        store.keys[stubKeyId] = stubBoundPrivateKeyData;

        const privateKeyData = await store.fetchSessionKey(stubKeyId, stubRecipientPublicKey);

        expect(privateKeyData).toBe(stubPrivateKey);
      });

      test('Keys bound to another recipient should not be returned', async () => {
        const store = new StubPrivateKeyStore();
        store.keys[stubKeyId] = {
          ...stubBoundPrivateKeyData,
          recipientPublicKeyDigest: `not ${stubBoundPrivateKeyData.recipientPublicKeyDigest}`,
        };

        await expectPromiseToReject(
          store.fetchSessionKey(stubKeyId, stubRecipientPublicKey),
          new PrivateKeyStoreError(`Key ${stubKeyId} is bound to another recipient`),
        );
      });

      test('Node keys should not be returned', async () => {
        const store = new StubPrivateKeyStore();
        store.keys[stubKeyId] = { ...stubUnboundPrivateKeyData, type: 'node' as const };

        await expectPromiseToReject(
          store.fetchSessionKey(stubKeyId),
          new PrivateKeyStoreError(`Key ${stubKeyId} is not a session key`),
        );
      });

      test('Errors should be wrapped', async () => {
        const store = new StubPrivateKeyStore();

        await expectPromiseToReject(
          store.fetchSessionKey(stubKeyId),
          new PrivateKeyStoreError(
            `Failed to retrieve session key ${stubKeyId}: Unknown key ${stubKeyId}`,
          ),
        );
      });
    });
  });
});
