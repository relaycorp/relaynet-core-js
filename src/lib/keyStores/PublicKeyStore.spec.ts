import {
  derSerializePublicKey,
  generateECDHKeyPair,
  generateRSAKeyPair,
  getIdFromIdentityKey,
} from '../crypto_wrappers/keys';
import { KeyStoreError } from './KeyStoreError';
import { SessionPublicKeyData } from './PublicKeyStore';
import { MockPublicKeyStore } from './testMocks';

const STORE = new MockPublicKeyStore();
beforeEach(() => {
  STORE.clear();
});

describe('Identity keys', () => {
  let publicKey: CryptoKey;
  let peerId: string;
  beforeAll(async () => {
    const keyPair = await generateRSAKeyPair();
    publicKey = keyPair.publicKey;
    peerId = await getIdFromIdentityKey(publicKey);
  });

  describe('saveIdentityKey', () => {
    test('Key should be stored', async () => {
      await STORE.saveIdentityKey(publicKey);

      expect(STORE.identityKeys).toHaveProperty(peerId, await derSerializePublicKey(publicKey));
    });
  });

  describe('retrieveIdentityKey', () => {
    test('Key should be returned if it exists', async () => {
      await STORE.saveIdentityKey(publicKey);

      const publicKeyRetrieved = await STORE.retrieveIdentityKey(peerId);

      await expect(derSerializePublicKey(publicKeyRetrieved!)).resolves.toEqual(
        await derSerializePublicKey(publicKey),
      );
    });

    test('Null should be returned if it does not exist', async () => {
      await expect(STORE.retrieveIdentityKey(peerId)).resolves.toBeNull();
    });
  });
});

describe('Session keys', () => {
  const CREATION_DATE = new Date();

  const sessionKeyId = Buffer.from([1, 3, 5, 7, 9]);
  let sessionPublicKey: CryptoKey;
  const peerId = '0deadbeef';
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
      STORE.registerSessionKey(keyData, peerId);

      const key = await STORE.retrieveLastSessionKey(peerId);
      expect(key?.keyId).toEqual(sessionKeyId);
      expect(await derSerializePublicKey(key!.publicKey)).toEqual(keyData.publicKeyDer);
    });

    test('Null should be returned if key for recipient does not exist', async () => {
      await expect(STORE.retrieveLastSessionKey(peerId)).resolves.toBeNull();
    });

    test('Retrieval errors should be wrapped', async () => {
      const fetchError = new Error('Ho noes');

      const bogusStore = new MockPublicKeyStore(false, fetchError);

      await expect(bogusStore.retrieveLastSessionKey(peerId)).rejects.toEqual(
        new KeyStoreError(fetchError, 'Failed to retrieve key'),
      );
    });
  });

  describe('saveSessionKey', () => {
    test('Key data should be saved if there is no prior key for recipient', async () => {
      await STORE.saveSessionKey(
        { keyId: sessionKeyId, publicKey: sessionPublicKey },
        peerId,
        CREATION_DATE,
      );

      const keyData = STORE.sessionKeys[peerId];
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
      STORE.registerSessionKey(oldKeyData, peerId);

      const newPublicKeyId = Buffer.concat([sessionKeyId, Buffer.from([1, 0])]);
      const newPublicKey = (await generateECDHKeyPair()).publicKey;
      const newPublicKeyDate = new Date(CREATION_DATE);
      newPublicKeyDate.setHours(newPublicKeyDate.getHours() + 1);
      await STORE.saveSessionKey(
        { publicKey: newPublicKey, keyId: newPublicKeyId },
        peerId,
        newPublicKeyDate,
      );

      const keyData = STORE.sessionKeys[peerId];
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
      STORE.registerSessionKey(currentKeyData, peerId);

      const olderPublicKeyId = Buffer.concat([sessionKeyId, sessionKeyId]);
      const olderPublicKey = (await generateECDHKeyPair()).publicKey;
      const olderPublicKeyDate = new Date(CREATION_DATE);
      olderPublicKeyDate.setHours(olderPublicKeyDate.getHours() - 1);
      await STORE.saveSessionKey(
        { publicKey: olderPublicKey, keyId: olderPublicKeyId },
        peerId,
        olderPublicKeyDate,
      );

      const keyData = STORE.sessionKeys[peerId];
      expect(keyData).toEqual(currentKeyData);
    });

    test('Any error should be propagated', async () => {
      const bogusStore = new MockPublicKeyStore(true);

      await expect(
        bogusStore.saveSessionKey(
          { keyId: sessionKeyId, publicKey: sessionPublicKey },
          peerId,
          CREATION_DATE,
        ),
      ).rejects.toEqual(new KeyStoreError('Failed to save public session key: Denied'));
    });
  });
});
