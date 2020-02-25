/* tslint:disable:max-classes-per-file */
import {
  derDeserializeECDHPrivateKey,
  derDeserializeRSAPrivateKey,
  derSerializePrivateKey,
  getPublicKeyDigestHex,
} from './crypto_wrappers/keys';
import RelaynetError from './RelaynetError';

export interface PrivateKeyData {
  readonly keyDer: Buffer;
  readonly type: 'node' | 'session';
  readonly recipientPublicKeyDigest?: string;
}

export class PrivateKeyStoreError extends RelaynetError {}

export abstract class PrivateKeyStore {
  public async fetchNodeKey(keyId: Buffer): Promise<CryptoKey> {
    const keyData = await this.fetchKeyOrThrowError(keyId);

    if (keyData.type !== 'node') {
      throw new PrivateKeyStoreError(`Key ${keyId} is not a node key`);
    }

    return derDeserializeRSAPrivateKey(keyData.keyDer, {
      hash: { name: 'SHA-256' },
      name: 'RSA-PSS',
    });
  }

  public async fetchSessionKey(keyId: Buffer, recipientPublicKey: CryptoKey): Promise<CryptoKey> {
    const keyData = await this.fetchKeyOrThrowError(keyId);

    if (keyData.type !== 'session') {
      throw new PrivateKeyStoreError(`Key ${keyId} is not a session key`);
    }

    if (keyData.recipientPublicKeyDigest) {
      const recipientPublicKeyDigest = await getPublicKeyDigestHex(recipientPublicKey);
      if (recipientPublicKeyDigest !== keyData.recipientPublicKeyDigest) {
        throw new PrivateKeyStoreError(`Key ${keyId} is bound to another recipient`);
      }
    }

    return derDeserializeECDHPrivateKey(keyData.keyDer, 'P-256');
  }

  public async saveNodeKey(privateKey: CryptoKey, keyId: Buffer): Promise<void> {
    const privateKeyDer = await derSerializePrivateKey(privateKey);
    const privateKeyData: PrivateKeyData = {
      keyDer: privateKeyDer,
      type: 'node',
    };
    await this.saveKeyOrThrowError(privateKeyData, keyId);
  }

  public async saveSessionKey(
    privateKey: CryptoKey,
    keyId: Buffer,
    recipientPublicKey?: CryptoKey,
  ): Promise<void> {
    const privateKeyData: PrivateKeyData = {
      keyDer: await derSerializePrivateKey(privateKey),
      recipientPublicKeyDigest: recipientPublicKey
        ? await getPublicKeyDigestHex(recipientPublicKey)
        : undefined,
      type: 'session',
    };
    await this.saveKeyOrThrowError(privateKeyData, keyId);
  }

  protected abstract async fetchKey(keyId: string): Promise<PrivateKeyData>;

  protected abstract async saveKey(privateKeyData: PrivateKeyData, keyId: string): Promise<void>;

  private async fetchKeyOrThrowError(keyId: Buffer): Promise<PrivateKeyData> {
    const keyIdBase64 = keyId.toString('base64');
    try {
      return await this.fetchKey(keyIdBase64);
    } catch (error) {
      throw new PrivateKeyStoreError(error, `Failed to retrieve key`);
    }
  }

  private async saveKeyOrThrowError(privateKeyData: PrivateKeyData, keyId: Buffer): Promise<void> {
    const keyIdBase64 = keyId.toString('base64');
    try {
      await this.saveKey(privateKeyData, keyIdBase64);
    } catch (error) {
      throw new PrivateKeyStoreError(error, `Failed to save key`);
    }
  }
}
