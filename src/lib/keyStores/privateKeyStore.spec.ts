import {
  derSerializePrivateKey,
  generateRSAKeyPair,
  getPrivateAddressFromIdentityKey,
} from '../crypto_wrappers/keys';
import { SessionKeyPair } from '../SessionKeyPair';
import { PrivateKeyStoreError, SessionPrivateKeyData } from './privateKeyStore';
import { MockPrivateKeyStore } from './testMocks';
import UnknownKeyError from './UnknownKeyError';

describe('PrivateKeyStore', () => {
  const MOCK_STORE = new MockPrivateKeyStore();
  beforeEach(() => {
    MOCK_STORE.clear();
  });

  describe('Identity keys', () => {
    let privateKey: CryptoKey;
    let privateAddress: string;
    beforeAll(async () => {
      const keyPair = await generateRSAKeyPair();
      privateKey = keyPair.privateKey;
      privateAddress = await getPrivateAddressFromIdentityKey(keyPair.publicKey);
    });

    describe('saveIdentityKey', () => {
      test('Key should be stored', async () => {
        await MOCK_STORE.saveIdentityKey(privateKey);

        expect(MOCK_STORE.identityKeys[privateAddress]).toEqual(
          await derSerializePrivateKey(privateKey),
        );
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore(true);

        await expect(store.saveIdentityKey(privateKey)).rejects.toThrowWithMessage(
          PrivateKeyStoreError,
          `Failed to save key for ${privateAddress}: Denied`,
        );
      });
    });

    describe('retrieveIdentityKey', () => {
      test('Existing key pair should be returned', async () => {
        await MOCK_STORE.saveIdentityKey(privateKey);

        const privateKeyRetrieved = await MOCK_STORE.retrieveIdentityKey(privateAddress);

        await expect(derSerializePrivateKey(privateKeyRetrieved)).resolves.toEqual(
          await derSerializePrivateKey(privateKey),
        );
      });

      test('UnknownKeyError should be thrown if key pair does not exist', async () => {
        await expect(MOCK_STORE.retrieveIdentityKey(privateAddress)).rejects.toThrowWithMessage(
          UnknownKeyError,
          `Identity key for ${privateAddress} doesn't exist`,
        );
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore(false, true);

        await expect(store.retrieveIdentityKey(privateAddress)).rejects.toThrowWithMessage(
          PrivateKeyStoreError,
          `Failed to retrieve key for ${privateAddress}: Denied`,
        );
      });
    });
  });

  describe('Session keys', () => {
    let sessionKeyPair: SessionKeyPair;
    let sessionKeyIdHex: string;
    beforeAll(async () => {
      sessionKeyPair = await SessionKeyPair.generate();
      sessionKeyIdHex = sessionKeyPair.sessionKey.keyId.toString('hex');
    });

    const PEER_PRIVATE_ADDRESS = '0deadbeef';

    describe('saveUnboundSessionKey', () => {
      test('Key should be stored', async () => {
        await MOCK_STORE.saveUnboundSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
        );

        expect(MOCK_STORE.sessionKeys).toHaveProperty<SessionPrivateKeyData>(sessionKeyIdHex, {
          keySerialized: await derSerializePrivateKey(sessionKeyPair.privateKey),
        });
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore(true);

        await expect(
          store.saveUnboundSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId),
        ).rejects.toThrowWithMessage(
          PrivateKeyStoreError,
          `Failed to save key ${sessionKeyIdHex}: Denied`,
        );
      });
    });

    describe('fetchUnboundSessionKey', () => {
      test('Existing key should be returned', async () => {
        await MOCK_STORE.saveUnboundSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
        );

        const keySerialized = await MOCK_STORE.retrieveUnboundSessionKey(
          sessionKeyPair.sessionKey.keyId,
        );

        expect(await derSerializePrivateKey(keySerialized)).toEqual(
          await derSerializePrivateKey(sessionKeyPair.privateKey),
        );
      });

      test('UnknownKeyError should be thrown if key id does not exist', async () => {
        await expect(
          MOCK_STORE.retrieveUnboundSessionKey(sessionKeyPair.sessionKey.keyId),
        ).rejects.toBeInstanceOf(UnknownKeyError);
      });

      test('Subsequent session keys should not be returned', async () => {
        await MOCK_STORE.saveBoundSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
          PEER_PRIVATE_ADDRESS,
        );

        await expect(
          MOCK_STORE.retrieveUnboundSessionKey(sessionKeyPair.sessionKey.keyId),
        ).rejects.toThrowWithMessage(UnknownKeyError, `Key ${sessionKeyIdHex} is bound`);
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore(false, true);

        await expect(
          store.retrieveUnboundSessionKey(sessionKeyPair.sessionKey.keyId),
        ).rejects.toEqual(new PrivateKeyStoreError('Failed to retrieve key: Denied'));
      });
    });

    describe('saveBoundSessionKey', () => {
      test('Bound key should be stored', async () => {
        await MOCK_STORE.saveBoundSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
          PEER_PRIVATE_ADDRESS,
        );

        expect(MOCK_STORE.sessionKeys).toHaveProperty<SessionPrivateKeyData>(sessionKeyIdHex, {
          keySerialized: await derSerializePrivateKey(sessionKeyPair.privateKey),
          peerPrivateAddress: PEER_PRIVATE_ADDRESS,
        });
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore(true);

        await expect(
          store.saveBoundSessionKey(
            sessionKeyPair.privateKey,
            sessionKeyPair.sessionKey.keyId,
            PEER_PRIVATE_ADDRESS,
          ),
        ).rejects.toThrowWithMessage(
          PrivateKeyStoreError,
          `Failed to save key ${sessionKeyIdHex}: Denied`,
        );
      });
    });

    describe('fetchBoundKey', () => {
      test('Initial session keys should be returned', async () => {
        await MOCK_STORE.saveUnboundSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
        );

        const privateKey = await MOCK_STORE.retrieveSessionKey(
          sessionKeyPair.sessionKey.keyId,
          PEER_PRIVATE_ADDRESS,
        );

        expect(await derSerializePrivateKey(privateKey)).toEqual(
          await derSerializePrivateKey(privateKey),
        );
      });

      test('Subsequent session keys should be returned', async () => {
        await MOCK_STORE.saveBoundSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
          PEER_PRIVATE_ADDRESS,
        );

        const privateKey = await MOCK_STORE.retrieveSessionKey(
          sessionKeyPair.sessionKey.keyId,
          PEER_PRIVATE_ADDRESS,
        );

        expect(await derSerializePrivateKey(privateKey)).toEqual(
          await derSerializePrivateKey(privateKey),
        );
      });

      test('UnknownKeyError should be thrown if key pair does not exist', async () => {
        await expect(
          MOCK_STORE.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, PEER_PRIVATE_ADDRESS),
        ).rejects.toBeInstanceOf(UnknownKeyError);
      });

      test('Keys bound to another recipient should not be returned', async () => {
        await MOCK_STORE.saveBoundSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPair.sessionKey.keyId,
          PEER_PRIVATE_ADDRESS,
        );

        const invalidPeerPrivateAddress = `not ${PEER_PRIVATE_ADDRESS}`;
        await expect(
          MOCK_STORE.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, invalidPeerPrivateAddress),
        ).rejects.toThrowWithMessage(
          UnknownKeyError,
          `Session key ${sessionKeyIdHex} is bound to another recipient ` +
            `(${PEER_PRIVATE_ADDRESS}, not ${invalidPeerPrivateAddress})`,
        );
      });

      test('Errors should be wrapped', async () => {
        const store = new MockPrivateKeyStore(false, true);

        await expect(
          store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, PEER_PRIVATE_ADDRESS),
        ).rejects.toEqual(new PrivateKeyStoreError('Failed to retrieve key: Denied'));
      });
    });
  });
});
