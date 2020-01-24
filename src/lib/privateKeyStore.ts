/* tslint:disable:max-classes-per-file */
import { getPublicKeyDigestHex } from './crypto_wrappers/_utils';
import { derDeserializeECDHPrivateKey, derDeserializeRSAPrivateKey } from './crypto_wrappers/keys';
import RelaynetError from './RelaynetError';

export interface PrivateKeyData {
  readonly keyDer: Buffer;
  readonly type: 'node' | 'session';
  readonly recipientPublicKeyDigest?: string;
}

export class PrivateKeyStoreError extends RelaynetError {}

export abstract class PrivateKeyStore {
  public async fetchNodeKey(keyId: string): Promise<CryptoKey> {
    const keyData = await this.fetchKeyOrThrowError(keyId);

    if (keyData.type !== 'node') {
      throw new PrivateKeyStoreError(`Key ${keyId} is not a node key`);
    }

    return derDeserializeRSAPrivateKey(keyData.keyDer, {
      hash: { name: 'SHA-256' },
      name: 'RSA-PSS',
    });
  }

  // @ts-ignore
  public async fetchSessionKey(keyId: string, recipientPublicKey?: CryptoKey): Promise<CryptoKey> {
    const keyData = await this.fetchKeyOrThrowError(keyId);

    if (keyData.type !== 'session') {
      throw new PrivateKeyStoreError(`Key ${keyId} is not a session key`);
    }

    if (recipientPublicKey) {
      const recipientPublicKeyDigest = await getPublicKeyDigestHex(recipientPublicKey);
      if (recipientPublicKeyDigest !== keyData.recipientPublicKeyDigest) {
        throw new PrivateKeyStoreError(`Key ${keyId} is bound to another recipient`);
      }
    }

    return derDeserializeECDHPrivateKey(keyData.keyDer, 'P-256');
  }

  protected abstract async fetchKey(keyId: string): Promise<PrivateKeyData>;

  private async fetchKeyOrThrowError(keyId: string): Promise<PrivateKeyData> {
    try {
      return await this.fetchKey(keyId);
    } catch (error) {
      throw new PrivateKeyStoreError(error, `Failed to retrieve session key ${keyId}`);
    }
  }

  // public async saveNodeKey(privateKey: CryptoKey, keyId: number): Promise<void>;
  // public async saveSessionKey(
  //   privateKey: CryptoKey,
  //   keyId: number,
  //   recipientPublicKey: CryptoKey,
  // ): Promise<void>;
  // protected abstract async saveKey(privateKeyData: PrivateKeyData, keyId: number): Promise<void>;
}
