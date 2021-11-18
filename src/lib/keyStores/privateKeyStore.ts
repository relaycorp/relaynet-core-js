/* tslint:disable:max-classes-per-file */

import bufferToArray from 'buffer-to-arraybuffer';

import {
  derDeserializeECDHPrivateKey,
  derDeserializeRSAPrivateKey,
  derSerializePrivateKey,
} from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import RelaynetError from '../RelaynetError';
import UnknownKeyError from './UnknownKeyError';

export interface BasePrivateKeyData {
  readonly keyDer: Buffer;
}

/**
 * Data for the private key of a node key pair.
 */
export interface NodePrivateKeyData extends BasePrivateKeyData {
  readonly type: 'node';
  readonly certificateDer: Buffer;
}

/**
 * Data for a private key of a session key pair not bound to a specific recipient.
 */
export interface InitialSessionPrivateKeyData extends BasePrivateKeyData {
  readonly type: 'session-initial';
}

/**
 * Data for a private key of a session key pair bound to a specific recipient.
 *
 * In other words, this is for subsequent session keys.
 */
export interface SubsequentSessionPrivateKeyData extends BasePrivateKeyData {
  readonly type: 'session-subsequent';

  readonly peerPrivateAddress: string;
}

export type PrivateKeyData =
  | NodePrivateKeyData
  | InitialSessionPrivateKeyData
  | SubsequentSessionPrivateKeyData;

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
      throw new UnknownKeyError(`Key ${keyId.toString('hex')} is not a node key`);
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
  public async fetchInitialSessionKey(keyId: Buffer): Promise<CryptoKey> {
    const keyData = await this.fetchKeyOrThrowError(keyId);

    if (keyData.type !== 'session-initial') {
      throw new UnknownKeyError(`Key ${keyId.toString('hex')} is not an initial session key`);
    }

    return derDeserializeECDHPrivateKey(keyData.keyDer, 'P-256');
  }

  /**
   * Retrieve private session key, regardless of whether it's an initial key or not.
   *
   * @param keyId The key pair id (typically the serial number)
   * @param peerPrivateAddress The private address of the recipient, in case the key is bound to
   *    a recipient
   * @throws UnknownKeyError when the key does not exist
   * @throws PrivateKeyStoreError when the look up could not be done
   */
  public async fetchSessionKey(keyId: Buffer, peerPrivateAddress: string): Promise<CryptoKey> {
    const keyData = await this.fetchKeyOrThrowError(keyId);
    const keyIdHex = keyId.toString('hex');

    if (keyData.type === 'node') {
      throw new UnknownKeyError(`Key ${keyIdHex} is not a session key`);
    }

    if (keyData.type === 'session-subsequent') {
      if (peerPrivateAddress !== keyData.peerPrivateAddress) {
        throw new UnknownKeyError(
          `Session key ${keyIdHex} is bound to another recipient ` +
            `(${keyData.peerPrivateAddress}, not ${peerPrivateAddress})`,
        );
      }
    }

    return derDeserializeECDHPrivateKey(keyData.keyDer, 'P-256');
  }

  public async saveNodeKey(privateKey: CryptoKey, certificate: Certificate): Promise<void> {
    const privateKeyDer = await derSerializePrivateKey(privateKey);
    const privateKeyData: NodePrivateKeyData = {
      certificateDer: Buffer.from(certificate.serialize()),
      keyDer: privateKeyDer,
      type: 'node',
    };
    await this.saveKeyOrWrapError(privateKeyData, certificate.getSerialNumber());
  }

  public async saveInitialSessionKey(privateKey: CryptoKey, keyId: Buffer): Promise<void> {
    const privateKeyDer = await derSerializePrivateKey(privateKey);
    const privateKeyData: InitialSessionPrivateKeyData = {
      keyDer: privateKeyDer,
      type: 'session-initial',
    };
    await this.saveKeyOrWrapError(privateKeyData, keyId);
  }

  public async saveSubsequentSessionKey(
    privateKey: CryptoKey,
    keyId: Buffer,
    peerPrivateAddress: string,
  ): Promise<void> {
    const privateKeyData: SubsequentSessionPrivateKeyData = {
      keyDer: await derSerializePrivateKey(privateKey),
      peerPrivateAddress,
      type: 'session-subsequent',
    };
    await this.saveKeyOrWrapError(privateKeyData, keyId);
  }

  protected abstract async fetchKey(keyId: string): Promise<PrivateKeyData | null>;

  protected abstract async saveKey(privateKeyData: PrivateKeyData, keyId: string): Promise<void>;

  private async fetchKeyOrThrowError(keyId: Buffer): Promise<PrivateKeyData> {
    const keyIdHex = keyId.toString('hex');
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

  private async saveKeyOrWrapError(privateKeyData: PrivateKeyData, keyId: Buffer): Promise<void> {
    const keyIdString = keyId.toString('hex');
    try {
      await this.saveKey(privateKeyData, keyIdString);
    } catch (error) {
      throw new PrivateKeyStoreError(error, `Failed to save key`);
    }
  }
}
