import { derDeserializeECDHPublicKey, derSerializePublicKey } from '../crypto_wrappers/keys';
import { SessionKey } from '../SessionKey';
import PublicKeyStoreError from './PublicKeyStoreError';

export interface SessionPublicKeyData {
  readonly publicKeyId: Buffer;
  readonly publicKeyDer: Buffer;
  readonly publicKeyCreationTime: Date;
}

export abstract class PublicKeyStore {
  public async fetchLastSessionKey(peerPrivateAddress: string): Promise<SessionKey | null> {
    const keyData = await this.fetchKeyDataOrThrowError(peerPrivateAddress);
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
    const priorKeyData = await this.fetchKeyDataOrThrowError(peerPrivateAddress);
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
      throw new PublicKeyStoreError(error, 'Failed to save public session key');
    }
  }

  protected abstract async fetchKey(
    peerPrivateAddress: string,
  ): Promise<SessionPublicKeyData | null>;

  protected abstract async saveKey(
    keyData: SessionPublicKeyData,
    peerPrivateAddress: string,
  ): Promise<void>;

  private async fetchKeyDataOrThrowError(
    peerPrivateAddress: string,
  ): Promise<SessionPublicKeyData | null> {
    try {
      return await this.fetchKey(peerPrivateAddress);
    } catch (error) {
      throw new PublicKeyStoreError(error, 'Failed to retrieve key');
    }
  }
}
