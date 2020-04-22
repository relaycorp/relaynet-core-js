/* tslint:disable:no-let no-object-mutation */

import { generateStubCert } from '../_test_utils';
import { derSerializePublicKey, generateECDHKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { MockPublicKeyStore } from './_testMocks';
import { SessionPublicKeyData } from './publicKeyStore';

describe('PublicKeyStore', () => {
  const CREATION_DATE = new Date();
  let PUBLIC_KEY: CryptoKey;
  const KEY_ID = Buffer.from([1, 3, 5, 7, 9]);
  let CERTIFICATE: Certificate;
  beforeAll(async () => {
    const keyPair = await generateECDHKeyPair();
    PUBLIC_KEY = keyPair.publicKey;

    CERTIFICATE = await generateStubCert();
  });

  describe('fetchLastSessionKey', () => {
    test('Key data should be returned if key for recipient exists', async () => {
      const store = new MockPublicKeyStore();
      const keyData: SessionPublicKeyData = {
        publicKeyCreationTime: CREATION_DATE,
        publicKeyDer: await derSerializePublicKey(PUBLIC_KEY),
        publicKeyId: KEY_ID,
      };
      store.registerKey(keyData, await CERTIFICATE.calculateSubjectPrivateAddress());

      const key = await store.fetchLastSessionKey(CERTIFICATE);
      expect(key.keyId).toEqual(KEY_ID);
      expect(await derSerializePublicKey(key.publicKey)).toEqual(keyData.publicKeyDer);
    });

    test('An error should be thrown if key for recipient does not exist', async () => {
      const store = new MockPublicKeyStore();

      await expect(store.fetchLastSessionKey(CERTIFICATE)).rejects.toHaveProperty(
        'message',
        expect.stringMatching(/^Failed to retrieve key: Unknown key/),
      );
    });
  });

  describe('saveSessionKey', () => {
    test('Key data should be saved if there is no prior key for recipient', async () => {
      const store = new MockPublicKeyStore();

      await store.saveSessionKey(
        { keyId: KEY_ID, publicKey: PUBLIC_KEY },
        CERTIFICATE,
        CREATION_DATE,
      );

      const keyData = store.keys[await CERTIFICATE.calculateSubjectPrivateAddress()];
      const expectedKeyData: SessionPublicKeyData = {
        publicKeyCreationTime: CREATION_DATE,
        publicKeyDer: await derSerializePublicKey(PUBLIC_KEY),
        publicKeyId: KEY_ID,
      };
      expect(keyData).toEqual(expectedKeyData);
    });

    test('Key data should be saved if prior key is older', async () => {
      const store = new MockPublicKeyStore();
      const oldKeyData: SessionPublicKeyData = {
        publicKeyCreationTime: CREATION_DATE,
        publicKeyDer: await derSerializePublicKey(PUBLIC_KEY),
        publicKeyId: KEY_ID,
      };
      store.registerKey(oldKeyData, await CERTIFICATE.calculateSubjectPrivateAddress());

      const newPublicKeyId = Buffer.concat([KEY_ID, Buffer.from([1, 0])]);
      const newPublicKey = (await generateECDHKeyPair()).publicKey;
      const newPublicKeyDate = new Date(CREATION_DATE);
      newPublicKeyDate.setHours(newPublicKeyDate.getHours() + 1);
      await store.saveSessionKey(
        { publicKey: newPublicKey, keyId: newPublicKeyId },
        CERTIFICATE,
        newPublicKeyDate,
      );

      const keyData = store.keys[await CERTIFICATE.calculateSubjectPrivateAddress()];
      const expectedKeyData: SessionPublicKeyData = {
        publicKeyCreationTime: newPublicKeyDate,
        publicKeyDer: await derSerializePublicKey(newPublicKey),
        publicKeyId: newPublicKeyId,
      };
      expect(keyData).toEqual(expectedKeyData);
    });

    test('Key data should not be saved if prior key is newer', async () => {
      const store = new MockPublicKeyStore();
      const currentKeyData: SessionPublicKeyData = {
        publicKeyCreationTime: CREATION_DATE,
        publicKeyDer: await derSerializePublicKey(PUBLIC_KEY),
        publicKeyId: KEY_ID,
      };
      store.registerKey(currentKeyData, await CERTIFICATE.calculateSubjectPrivateAddress());

      const olderPublicKeyId = Buffer.concat([KEY_ID, KEY_ID]);
      const olderPublicKey = (await generateECDHKeyPair()).publicKey;
      const olderPublicKeyDate = new Date(CREATION_DATE);
      olderPublicKeyDate.setHours(olderPublicKeyDate.getHours() - 1);
      await store.saveSessionKey(
        { publicKey: olderPublicKey, keyId: olderPublicKeyId },
        CERTIFICATE,
        olderPublicKeyDate,
      );

      const keyData = store.keys[await CERTIFICATE.calculateSubjectPrivateAddress()];
      expect(keyData).toEqual(currentKeyData);
    });
  });
});
