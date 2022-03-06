import { derSerializePublicKey, generateECDHKeyPair } from '../crypto_wrappers/keys';
import { SessionPublicKeyData } from './PublicKeyStore';
import PublicKeyStoreError from './PublicKeyStoreError';
import { MockPublicKeyStore } from './testMocks';

const MOCK_STORE = new MockPublicKeyStore();
beforeEach(() => {
  MOCK_STORE.clear();
});

describe('Session keys', () => {
  const CREATION_DATE = new Date();

  const sessionKeyId = Buffer.from([1, 3, 5, 7, 9]);
  let sessionPublicKey: CryptoKey;
  const peerPrivateAddress = '0deadbeef';
  beforeAll(async () => {
    const keyPair = await generateECDHKeyPair();
    sessionPublicKey = keyPair.publicKey;
  });

  describe('retrieveLastSessionKey', () => {
    test('Key data should be returned if key for recipient exists', async () => {
      const keyData: SessionPublicKeyData = {
        publicKeyCreationTime: CREATION_DATE,
        publicKeyDer: await derSerializePublicKey(sessionPublicKey),
        publicKeyId: sessionKeyId,
      };
      MOCK_STORE.registerKey(keyData, peerPrivateAddress);

      const key = await MOCK_STORE.retrieveLastSessionKey(peerPrivateAddress);
      expect(key?.keyId).toEqual(sessionKeyId);
      expect(await derSerializePublicKey(key!.publicKey)).toEqual(keyData.publicKeyDer);
    });

    test('Null should be returned if key for recipient does not exist', async () => {
      await expect(MOCK_STORE.retrieveLastSessionKey(peerPrivateAddress)).resolves.toBeNull();
    });

    test('Retrieval errors should be wrapped', async () => {
      const fetchError = new Error('Ho noes');

      const bogusStore = new MockPublicKeyStore(false, fetchError);

      await expect(bogusStore.retrieveLastSessionKey(peerPrivateAddress)).rejects.toEqual(
        new PublicKeyStoreError(fetchError, 'Failed to retrieve key'),
      );
    });
  });

  describe('saveSessionKey', () => {
    test('Key data should be saved if there is no prior key for recipient', async () => {
      await MOCK_STORE.saveSessionKey(
        { keyId: sessionKeyId, publicKey: sessionPublicKey },
        peerPrivateAddress,
        CREATION_DATE,
      );

      const keyData = MOCK_STORE.sessionKeys[peerPrivateAddress];
      const expectedKeyData: SessionPublicKeyData = {
        publicKeyCreationTime: CREATION_DATE,
        publicKeyDer: await derSerializePublicKey(sessionPublicKey),
        publicKeyId: sessionKeyId,
      };
      expect(keyData).toEqual(expectedKeyData);
    });

    test('Key data should be saved if prior key is older', async () => {
      const oldKeyData: SessionPublicKeyData = {
        publicKeyCreationTime: CREATION_DATE,
        publicKeyDer: await derSerializePublicKey(sessionPublicKey),
        publicKeyId: sessionKeyId,
      };
      MOCK_STORE.registerKey(oldKeyData, peerPrivateAddress);

      const newPublicKeyId = Buffer.concat([sessionKeyId, Buffer.from([1, 0])]);
      const newPublicKey = (await generateECDHKeyPair()).publicKey;
      const newPublicKeyDate = new Date(CREATION_DATE);
      newPublicKeyDate.setHours(newPublicKeyDate.getHours() + 1);
      await MOCK_STORE.saveSessionKey(
        { publicKey: newPublicKey, keyId: newPublicKeyId },
        peerPrivateAddress,
        newPublicKeyDate,
      );

      const keyData = MOCK_STORE.sessionKeys[peerPrivateAddress];
      const expectedKeyData: SessionPublicKeyData = {
        publicKeyCreationTime: newPublicKeyDate,
        publicKeyDer: await derSerializePublicKey(newPublicKey),
        publicKeyId: newPublicKeyId,
      };
      expect(keyData).toEqual(expectedKeyData);
    });

    test('Key data should not be saved if prior key is newer', async () => {
      const currentKeyData: SessionPublicKeyData = {
        publicKeyCreationTime: CREATION_DATE,
        publicKeyDer: await derSerializePublicKey(sessionPublicKey),
        publicKeyId: sessionKeyId,
      };
      MOCK_STORE.registerKey(currentKeyData, peerPrivateAddress);

      const olderPublicKeyId = Buffer.concat([sessionKeyId, sessionKeyId]);
      const olderPublicKey = (await generateECDHKeyPair()).publicKey;
      const olderPublicKeyDate = new Date(CREATION_DATE);
      olderPublicKeyDate.setHours(olderPublicKeyDate.getHours() - 1);
      await MOCK_STORE.saveSessionKey(
        { publicKey: olderPublicKey, keyId: olderPublicKeyId },
        peerPrivateAddress,
        olderPublicKeyDate,
      );

      const keyData = MOCK_STORE.sessionKeys[peerPrivateAddress];
      expect(keyData).toEqual(currentKeyData);
    });

    test('Any error should be propagated', async () => {
      const bogusStore = new MockPublicKeyStore(true);

      await expect(
        bogusStore.saveSessionKey(
          { keyId: sessionKeyId, publicKey: sessionPublicKey },
          peerPrivateAddress,
          CREATION_DATE,
        ),
      ).rejects.toEqual(new PublicKeyStoreError('Failed to save public session key: Denied'));
    });
  });
});
