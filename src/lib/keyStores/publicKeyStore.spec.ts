/* tslint:disable:no-let no-object-mutation */

import { generateStubCert } from '../_test_utils';
import { derSerializePublicKey, generateECDHKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { PublicKeyData, PublicKeyStore } from './publicKeyStore';

class MockPublicKeyStore extends PublicKeyStore {
  // tslint:disable-next-line:readonly-keyword
  public readonly keys: { [key: string]: PublicKeyData } = {};

  constructor(protected readonly failOnSave = false) {
    super();
  }

  public registerKey(keyData: PublicKeyData, peerPrivateAddress: string): void {
    this.keys[peerPrivateAddress] = keyData;
  }

  protected async fetchKey(peerPrivateAddress: string): Promise<PublicKeyData> {
    const keyData = this.keys[peerPrivateAddress];
    if (keyData === undefined) {
      throw new Error(`Unknown key ${peerPrivateAddress}`);
    }
    return keyData;
  }

  protected async saveKey(keyData: PublicKeyData, peerPrivateAddress: string): Promise<void> {
    if (this.failOnSave) {
      throw new Error('Denied');
    }
    this.keys[peerPrivateAddress] = keyData;
  }
}

describe('PublicKeyStore', () => {
  const CREATION_DATE = new Date();
  let PUBLIC_KEY: CryptoKey;
  let CERTIFICATE: Certificate;
  beforeAll(async () => {
    const keyPair = await generateECDHKeyPair();
    PUBLIC_KEY = keyPair.publicKey;

    CERTIFICATE = await generateStubCert();
  });

  describe('fetchLastSessionKey', () => {
    test('Key data should be returned if key for recipient exists', async () => {
      const store = new MockPublicKeyStore();
      const keyData: PublicKeyData = {
        publicKeyCreationTime: CREATION_DATE,
        publicKeyDer: await derSerializePublicKey(PUBLIC_KEY),
      };
      store.registerKey(keyData, await CERTIFICATE.calculateSubjectPrivateAddress());

      const key = await store.fetchLastSessionKey(CERTIFICATE);
      expect(await derSerializePublicKey(key)).toEqual(keyData.publicKeyDer);
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

      await store.saveSessionKey(PUBLIC_KEY, CERTIFICATE, CREATION_DATE);

      const keyData = store.keys[await CERTIFICATE.calculateSubjectPrivateAddress()];
      const expectedKeyData: PublicKeyData = {
        publicKeyCreationTime: CREATION_DATE,
        publicKeyDer: await derSerializePublicKey(PUBLIC_KEY),
      };
      expect(keyData).toEqual(expectedKeyData);
    });

    test('Key data should be saved if prior key is older', async () => {
      const store = new MockPublicKeyStore();
      const oldKeyData: PublicKeyData = {
        publicKeyCreationTime: CREATION_DATE,
        publicKeyDer: await derSerializePublicKey(PUBLIC_KEY),
      };
      store.registerKey(oldKeyData, await CERTIFICATE.calculateSubjectPrivateAddress());

      const newPublicKey = (await generateECDHKeyPair()).publicKey;
      const newPublicKeyDate = new Date(CREATION_DATE);
      newPublicKeyDate.setHours(newPublicKeyDate.getHours() + 1);
      await store.saveSessionKey(newPublicKey, CERTIFICATE, newPublicKeyDate);

      const keyData = store.keys[await CERTIFICATE.calculateSubjectPrivateAddress()];
      const expectedKeyData: PublicKeyData = {
        publicKeyCreationTime: newPublicKeyDate,
        publicKeyDer: await derSerializePublicKey(newPublicKey),
      };
      expect(keyData).toEqual(expectedKeyData);
    });

    test('Key data should not be saved if prior key is newer', async () => {
      const store = new MockPublicKeyStore();
      const currentKeyData: PublicKeyData = {
        publicKeyCreationTime: CREATION_DATE,
        publicKeyDer: await derSerializePublicKey(PUBLIC_KEY),
      };
      store.registerKey(currentKeyData, await CERTIFICATE.calculateSubjectPrivateAddress());

      const olderPublicKey = (await generateECDHKeyPair()).publicKey;
      const olderPublicKeyDate = new Date(CREATION_DATE);
      olderPublicKeyDate.setHours(olderPublicKeyDate.getHours() - 1);
      await store.saveSessionKey(olderPublicKey, CERTIFICATE, olderPublicKeyDate);

      const keyData = store.keys[await CERTIFICATE.calculateSubjectPrivateAddress()];
      const expectedKeyData: PublicKeyData = {
        publicKeyCreationTime: CREATION_DATE,
        publicKeyDer: await derSerializePublicKey(PUBLIC_KEY),
      };
      expect(keyData).toEqual(expectedKeyData);
    });
  });
});
