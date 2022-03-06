import { derDeserializeECDHPublicKey, derSerializePublicKey } from '../crypto_wrappers/keys';
import { SessionKey } from '../SessionKey';
import PublicKeyStoreError from './PublicKeyStoreError';

export interface SessionPublicKeyData {
  readonly publicKeyId: Buffer;
  readonly publicKeyDer: Buffer;
  readonly publicKeyCreationTime: Date;
}

export abstract class PublicKeyStore {
  public async retrieveLastSessionKey(peerPrivateAddress: string): Promise<SessionKey | null> {
    const keyData = await this.fetchKeyDataOrWrapError(peerPrivateAddress);
    if (!keyData) {
      return null;
    }
    const publicKey = await derDeserializeECDHPublicKey(keyData.publicKeyDer);
    return { publicKey, keyId: keyData.publicKeyId };
  }

  public async saveSessionKey(
    key: SessionKey,
    peerPrivateAddress: string,
    creationTime: Date,
  ): Promise<void> {
    const priorKeyData = await this.fetchKeyDataOrWrapError(peerPrivateAddress);
    if (priorKeyData && creationTime <= priorKeyData.publicKeyCreationTime) {
      return;
    }

    const keyData: SessionPublicKeyData = {
      publicKeyCreationTime: creationTime,
      publicKeyDer: await derSerializePublicKey(key.publicKey),
      publicKeyId: key.keyId,
    };
    try {
      await this.saveKey(keyData, peerPrivateAddress);
    } catch (error) {
      throw new PublicKeyStoreError(error as Error, 'Failed to save public session key');
    }
  }

  //endregion

  protected abstract fetchKey(peerPrivateAddress: string): Promise<SessionPublicKeyData | null>;

  protected abstract saveKey(
    keyData: SessionPublicKeyData,
    peerPrivateAddress: string,
  ): Promise<void>;

  private async fetchKeyDataOrWrapError(
    peerPrivateAddress: string,
  ): Promise<SessionPublicKeyData | null> {
    try {
      return await this.fetchKey(peerPrivateAddress);
    } catch (error) {
      throw new PublicKeyStoreError(error as Error, 'Failed to retrieve key');
    }
  }
}
