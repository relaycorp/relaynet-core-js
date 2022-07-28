import {
  derDeserializeECDHPublicKey,
  derDeserializeRSAPublicKey,
  derSerializePublicKey,
  getIdFromIdentityKey,
} from '../crypto_wrappers/keys';
import { SessionKey } from '../SessionKey';
import { KeyStoreError } from './KeyStoreError';

export interface SessionPublicKeyData {
  readonly publicKeyId: Buffer;
  readonly publicKeyDer: Buffer;
  readonly publicKeyCreationTime: Date;
}

export abstract class PublicKeyStore {
  //region Identity keys

  public async saveIdentityKey(key: CryptoKey): Promise<void> {
    const peerId = await getIdFromIdentityKey(key);
    const keySerialized = await derSerializePublicKey(key);
    await this.saveIdentityKeySerialized(keySerialized, peerId);
  }

  public async retrieveIdentityKey(peerId: string): Promise<CryptoKey | null> {
    const keySerialized = await this.retrieveIdentityKeySerialized(peerId);
    return keySerialized ? derDeserializeRSAPublicKey(keySerialized) : null;
  }

  //endregion
  //region Session keys

  public async saveSessionKey(key: SessionKey, peerId: string, creationTime: Date): Promise<void> {
    const priorKeyData = await this.fetchSessionKeyDataOrWrapError(peerId);
    if (priorKeyData && creationTime <= priorKeyData.publicKeyCreationTime) {
      return;
    }

    const keyData: SessionPublicKeyData = {
      publicKeyCreationTime: creationTime,
      publicKeyDer: await derSerializePublicKey(key.publicKey),
      publicKeyId: key.keyId,
    };
    try {
      await this.saveSessionKeyData(keyData, peerId);
    } catch (error) {
      throw new KeyStoreError(error as Error, 'Failed to save public session key');
    }
  }

  public async retrieveLastSessionKey(peerId: string): Promise<SessionKey | null> {
    const keyData = await this.fetchSessionKeyDataOrWrapError(peerId);
    if (!keyData) {
      return null;
    }
    const publicKey = await derDeserializeECDHPublicKey(keyData.publicKeyDer);
    return { publicKey, keyId: keyData.publicKeyId };
  }

  //endregion

  protected abstract retrieveIdentityKeySerialized(peerId: string): Promise<Buffer | null>;
  protected abstract retrieveSessionKeyData(peerId: string): Promise<SessionPublicKeyData | null>;

  protected abstract saveIdentityKeySerialized(
    keySerialized: Buffer,
    peerId: string,
  ): Promise<void>;
  protected abstract saveSessionKeyData(
    keyData: SessionPublicKeyData,
    peerId: string,
  ): Promise<void>;

  private async fetchSessionKeyDataOrWrapError(
    peerId: string,
  ): Promise<SessionPublicKeyData | null> {
    try {
      return await this.retrieveSessionKeyData(peerId);
    } catch (error) {
      throw new KeyStoreError(error as Error, 'Failed to retrieve key');
    }
  }
}
