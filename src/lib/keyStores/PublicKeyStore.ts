import {
  derDeserializeECDHPublicKey,
  derDeserializeRSAPublicKey,
  derSerializePublicKey,
  getPrivateAddressFromIdentityKey,
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
    const peerPrivateAddress = await getPrivateAddressFromIdentityKey(key);
    const keySerialized = await derSerializePublicKey(key);
    await this.saveIdentityKeySerialized(keySerialized, peerPrivateAddress);
  }

  public async retrieveIdentityKey(peerPrivateAddress: string): Promise<CryptoKey | null> {
    const keySerialized = await this.retrieveIdentityKeySerialized(peerPrivateAddress);
    return keySerialized ? derDeserializeRSAPublicKey(keySerialized) : null;
  }

  //endregion
  //region Session keys

  public async saveSessionKey(
    key: SessionKey,
    peerPrivateAddress: string,
    creationTime: Date,
  ): Promise<void> {
    const priorKeyData = await this.fetchSessionKeyDataOrWrapError(peerPrivateAddress);
    if (priorKeyData && creationTime <= priorKeyData.publicKeyCreationTime) {
      return;
    }

    const keyData: SessionPublicKeyData = {
      publicKeyCreationTime: creationTime,
      publicKeyDer: await derSerializePublicKey(key.publicKey),
      publicKeyId: key.keyId,
    };
    try {
      await this.saveSessionKeyData(keyData, peerPrivateAddress);
    } catch (error) {
      throw new KeyStoreError(error as Error, 'Failed to save public session key');
    }
  }

  public async retrieveLastSessionKey(peerPrivateAddress: string): Promise<SessionKey | null> {
    const keyData = await this.fetchSessionKeyDataOrWrapError(peerPrivateAddress);
    if (!keyData) {
      return null;
    }
    const publicKey = await derDeserializeECDHPublicKey(keyData.publicKeyDer);
    return { publicKey, keyId: keyData.publicKeyId };
  }

  //endregion

  protected abstract retrieveIdentityKeySerialized(
    peerPrivateAddress: string,
  ): Promise<Buffer | null>;
  protected abstract retrieveSessionKeyData(
    peerPrivateAddress: string,
  ): Promise<SessionPublicKeyData | null>;

  protected abstract saveIdentityKeySerialized(
    keySerialized: Buffer,
    peerPrivateAddress: string,
  ): Promise<void>;
  protected abstract saveSessionKeyData(
    keyData: SessionPublicKeyData,
    peerPrivateAddress: string,
  ): Promise<void>;

  private async fetchSessionKeyDataOrWrapError(
    peerPrivateAddress: string,
  ): Promise<SessionPublicKeyData | null> {
    try {
      return await this.retrieveSessionKeyData(peerPrivateAddress);
    } catch (error) {
      throw new KeyStoreError(error as Error, 'Failed to retrieve key');
    }
  }
}
