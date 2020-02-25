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
  public async fetchNodeKey(keyId: string | number): Promise<CryptoKey> {
    const keyData = await this.fetchKeyOrThrowError(keyId);

    if (keyData.type !== 'node') {
      throw new PrivateKeyStoreError(`Key ${keyId} is not a node key`);
    }

    return derDeserializeRSAPrivateKey(keyData.keyDer, {
      hash: { name: 'SHA-256' },
      name: 'RSA-PSS',
    });
  }

  public async fetchSessionKey(
    keyId: string | number,
    recipientPublicKey: CryptoKey,
  ): Promise<CryptoKey> {
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

  public async saveNodeKey(privateKey: CryptoKey, keyId: string | number): Promise<void> {
    const privateKeyDer = await derSerializePrivateKey(privateKey);
    const privateKeyData: PrivateKeyData = {
      keyDer: privateKeyDer,
      type: 'node',
    };
    try {
      await this.saveKey(privateKeyData, keyId.toString());
    } catch (error) {
      throw new PrivateKeyStoreError(error, `Failed to save node key ${keyId}`);
    }
  }

  public async saveSessionKey(
    privateKey: CryptoKey,
    keyId: string | number,
    recipientPublicKey?: CryptoKey,
  ): Promise<void> {
    const privateKeyData: PrivateKeyData = {
      keyDer: await derSerializePrivateKey(privateKey),
      recipientPublicKeyDigest: recipientPublicKey
        ? await getPublicKeyDigestHex(recipientPublicKey)
        : undefined,
      type: 'session',
    };
    try {
      await this.saveKey(privateKeyData, keyId.toString());
    } catch (error) {
      throw new PrivateKeyStoreError(error, `Failed to save session key ${keyId}`);
    }
  }

  protected abstract async fetchKey(keyId: string): Promise<PrivateKeyData>;

  protected abstract async saveKey(privateKeyData: PrivateKeyData, keyId: string): Promise<void>;

  private async fetchKeyOrThrowError(keyId: string | number): Promise<PrivateKeyData> {
    try {
      return await this.fetchKey(keyId.toString());
    } catch (error) {
      throw new PrivateKeyStoreError(error, `Failed to retrieve key ${keyId}`);
    }
  }
}
