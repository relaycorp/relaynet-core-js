/* tslint:disable:max-classes-per-file */

import bufferToArray from 'buffer-to-arraybuffer';

import {
  derDeserializeECDHPrivateKey,
  derDeserializeRSAPrivateKey,
  derSerializePrivateKey,
  getPublicKeyDigestHex,
} from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import RelaynetError from '../RelaynetError';
import UnknownKeyError from './UnknownKeyError';

export interface BasePrivateKeyData {
  readonly keyDer: Buffer;
  readonly type: 'node' | 'session-initial' | 'session-subsequent';
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
  readonly type: 'session-subsequent';

  // TODO: This should be the recipient address instead as it includes the type of public key
  readonly recipientPublicKeyDigest: string;
}

export type PrivateKeyData = UnboundPrivateKeyData | BoundPrivateKeyData;

/**
 * Error thrown when there was a failure in the communication with the backing service.
 */
export class PrivateKeyStoreError extends RelaynetError {}

export interface UnboundKeyPair {
  readonly privateKey: CryptoKey;
  readonly certificate: Certificate;
}

export abstract class PrivateKeyStore {
  /**
   * Return the private component of a node key pair.
   *
   * @param keyId The key pair id (typically the serial number)
   * @throws UnknownKeyError when the key does not exist
   * @throws PrivateKeyStoreError when the look up could not be done
   */
  public async fetchNodeKey(keyId: Buffer): Promise<UnboundKeyPair> {
    const keyData = await this.fetchKeyOrThrowError(keyId);

    if (keyData.type !== 'node') {
      throw new UnknownKeyError('Key is not a node key');
    }

    const privateKey = await derDeserializeRSAPrivateKey(keyData.keyDer, {
      hash: { name: 'SHA-256' },
      name: 'RSA-PSS',
    });
    return {
      certificate: Certificate.deserialize(bufferToArray(keyData.certificateDer)),
      privateKey,
    };
  }

  /**
   * Return the private component of an initial session key pair.
   *
   * @param keyId The key pair id (typically the serial number)
   * @throws UnknownKeyError when the key does not exist
   * @throws PrivateKeyStoreError when the look up could not be done
   */
  public async fetchInitialSessionKey(keyId: Buffer): Promise<UnboundKeyPair> {
    const keyData = await this.fetchKeyOrThrowError(keyId);

    if (keyData.type !== 'session-initial') {
      throw new UnknownKeyError('Key is not an initial session key');
    }

    return {
      certificate: Certificate.deserialize(bufferToArray(keyData.certificateDer)),
      privateKey: await derDeserializeECDHPrivateKey(keyData.keyDer, 'P-256'),
    };
  }

  /**
   * Retrieve private session key, regardless of whether it's an initial key or not.
   *
   * @param keyId The key pair id (typically the serial number)
   * @param recipientCertificate The certificate of the recipient, in case the key is bound to
   *    a recipient
   * @throws UnknownKeyError when the key does not exist
   * @throws PrivateKeyStoreError when the look up could not be done
   */
  public async fetchSessionKey(
    keyId: Buffer,
    recipientCertificate: Certificate,
  ): Promise<CryptoKey> {
    const keyData = await this.fetchKeyOrThrowError(keyId);

    if (keyData.type === 'node') {
      throw new UnknownKeyError('Key is not a session key');
    }

    if (keyData.type === 'session-subsequent') {
      const recipientPublicKeyDigest = await getPublicKeyDigestHex(
        await recipientCertificate.getPublicKey(),
      );
      if (recipientPublicKeyDigest !== keyData.recipientPublicKeyDigest) {
        throw new UnknownKeyError('Key is bound to another recipient');
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

  public async saveInitialSessionKey(
    privateKey: CryptoKey,
    certificate: Certificate,
  ): Promise<void> {
    const privateKeyDer = await derSerializePrivateKey(privateKey);
    const privateKeyData: UnboundPrivateKeyData = {
      certificateDer: Buffer.from(certificate.serialize()),
      keyDer: privateKeyDer,
      type: 'session-initial',
    };
    await this.saveKeyOrThrowError(privateKeyData, certificate.getSerialNumber());
  }

  public async saveSubsequentSessionKey(
    privateKey: CryptoKey,
    keyId: Buffer,
    recipientCertificate: Certificate,
  ): Promise<void> {
    const privateKeyData: BoundPrivateKeyData = {
      keyDer: await derSerializePrivateKey(privateKey),
      recipientPublicKeyDigest: await getPublicKeyDigestHex(
        await recipientCertificate.getPublicKey(),
      ),
      type: 'session-subsequent',
    };
    await this.saveKeyOrThrowError(privateKeyData, keyId);
  }

  protected abstract async fetchKey(keyId: string): Promise<PrivateKeyData | null>;

  protected abstract async saveKey(privateKeyData: PrivateKeyData, keyId: string): Promise<void>;

  private async fetchKeyOrThrowError(keyId: Buffer): Promise<PrivateKeyData> {
    const keyIdHex = keyId.toString('hex');
    // tslint:disable-next-line:no-let
    let key: PrivateKeyData | null;
    try {
      key = await this.fetchKey(keyIdHex);
    } catch (error) {
      throw new PrivateKeyStoreError(error, `Failed to retrieve key`);
    }
    if (key === null) {
      throw new UnknownKeyError(`Key ${keyIdHex} does not exist`);
    }
    return key;
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
