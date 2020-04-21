/* tslint:disable:max-classes-per-file */
import {
  derDeserializeECDHPrivateKey,
  derDeserializeRSAPrivateKey,
  derSerializePrivateKey,
  getPublicKeyDigestHex,
} from './crypto_wrappers/keys';
import Certificate from './crypto_wrappers/x509/Certificate';
import RelaynetError from './RelaynetError';

export interface BasePrivateKeyData {
  readonly keyDer: Buffer;
  readonly type: 'node' | 'session-initial' | 'session'; // TODO: Rename "session" to "session-subsequent"
}

/**
 * Data for a private key not bound to any recipient.
 *
 * In other words, this is for node keys and initial session keys.
 */
export interface UnboundPrivateKeyData extends BasePrivateKeyData {
  readonly type: 'node' | 'session-initial';
  readonly certificateDer: Buffer;
}

/**
 * Data for a private key bound to a specific recipient.
 *
 * In other words, this is for subsequent session keys.
 */
export interface BoundPrivateKeyData extends BasePrivateKeyData {
  readonly type: 'session';
  readonly recipientPublicKeyDigest: string;
}

export type PrivateKeyData = UnboundPrivateKeyData | BoundPrivateKeyData;

export class PrivateKeyStoreError extends RelaynetError {}

export interface UnboundKeyPair {
  readonly privateKey: CryptoKey;
  readonly certificate: Certificate;
}

export abstract class PrivateKeyStore {
  public async fetchNodeKey(keyIdHex: string): Promise<UnboundKeyPair> {
    const keyData = await this.fetchKeyOrThrowError(keyIdHex);

    if (keyData.type !== 'node') {
      throw new PrivateKeyStoreError(`Key ${keyIdHex} is not a node key`);
    }

    const privateKey = await derDeserializeRSAPrivateKey(keyData.keyDer, {
      hash: { name: 'SHA-256' },
      name: 'RSA-PSS',
    });
    return { certificate: undefined as any, privateKey };
  }

  public async fetchSessionKey(
    keyIdHex: string,
    recipientCertificate: Certificate,
  ): Promise<CryptoKey> {
    const keyData = await this.fetchKeyOrThrowError(keyIdHex);

    if (keyData.type !== 'session') {
      throw new PrivateKeyStoreError(`Key ${keyIdHex} is not a session key`);
    }

    if (keyData.recipientPublicKeyDigest) {
      const recipientPublicKeyDigest = await getPublicKeyDigestHex(
        await recipientCertificate.getPublicKey(),
      );
      if (recipientPublicKeyDigest !== keyData.recipientPublicKeyDigest) {
        throw new PrivateKeyStoreError(`Key ${keyIdHex} is bound to another recipient`);
      }
    }

    return derDeserializeECDHPrivateKey(keyData.keyDer, 'P-256');
  }

  public async saveNodeKey(privateKey: CryptoKey, certificate: Certificate): Promise<void> {
    const privateKeyDer = await derSerializePrivateKey(privateKey);
    const privateKeyData: UnboundPrivateKeyData = {
      certificateDer: Buffer.from(certificate.serialize()),
      keyDer: privateKeyDer,
      type: 'node',
    };
    await this.saveKeyOrThrowError(privateKeyData, certificate.getSerialNumber());
  }

  public async saveSessionKey(
    privateKey: CryptoKey,
    keyId: Buffer,
    recipientCertificate?: Certificate,
  ): Promise<void> {
    // TODO: FIX!
    // @ts-ignore
    const privateKeyData: PrivateKeyData = {
      keyDer: await derSerializePrivateKey(privateKey),
      recipientPublicKeyDigest: recipientCertificate
        ? await getPublicKeyDigestHex(await recipientCertificate.getPublicKey())
        : undefined,
      type: 'session',
    };
    await this.saveKeyOrThrowError(privateKeyData, keyId);
  }

  protected abstract async fetchKey(keyId: string): Promise<PrivateKeyData>;

  protected abstract async saveKey(privateKeyData: PrivateKeyData, keyId: string): Promise<void>;

  private async fetchKeyOrThrowError(keyIdHex: string): Promise<PrivateKeyData> {
    try {
      return await this.fetchKey(keyIdHex);
    } catch (error) {
      throw new PrivateKeyStoreError(error, `Failed to retrieve key`);
    }
  }

  private async saveKeyOrThrowError(privateKeyData: PrivateKeyData, keyId: Buffer): Promise<void> {
    const keyIdString = keyId.toString('hex');
    try {
      await this.saveKey(privateKeyData, keyIdString);
    } catch (error) {
      throw new PrivateKeyStoreError(error, `Failed to save key`);
    }
  }
}
