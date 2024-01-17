/* tslint:disable:max-classes-per-file */

import { generateRSAKeyPair, RSAKeyGenOptions } from '../crypto/keys/generation';
import { IdentityKeyPair } from '../IdentityKeyPair';
import { KeyStoreError } from './KeyStoreError';
import { UnknownKeyError } from './UnknownKeyError';
import {
  derDeserializeECDHPrivateKey,
  derDeserializeECDHPublicKey,
  derSerializePrivateKey,
  derSerializePublicKey,
} from '../crypto/keys/serialisation';
import { getIdFromIdentityKey } from '../crypto/keys/digest';
import { SessionKey } from '../SessionKey';

/**
 * Data for a private key of a session key pair.
 */
export interface SessionPrivateKeyData {
  readonly keySerialized: Buffer;
  readonly nodeId: string;
  readonly peerId?: string;
}

/**
 * Data for an unbound, private key of a session key pair.
 */
export interface UnboundSessionPrivateKeyData {
  readonly keyId: string;
  readonly keySerialized: Buffer;
}

export abstract class PrivateKeyStore {
  //region Identity keys

  public async generateIdentityKeyPair(
    keyOptions: Partial<RSAKeyGenOptions> = {},
  ): Promise<IdentityKeyPair> {
    const keyPair = await this.generateRSAKeyPair(keyOptions);
    const id = await getIdFromIdentityKey(keyPair.publicKey);
    try {
      await this.saveIdentityKey(id, keyPair.privateKey);
    } catch (err) {
      throw new KeyStoreError(err as Error, `Failed to save key for ${id}`);
    }
    return { ...keyPair, id };
  }

  /**
   * Return the private component of a node key pair if it exists.
   *
   * @param nodeId
   * @throws {KeyStoreError} if the backend failed to retrieve the key due to an error
   */
  public abstract retrieveIdentityKey(nodeId: string): Promise<CryptoKey | null>;

  //endregion
  //region Session keys

  public async saveSessionKey(
    privateKey: CryptoKey,
    keyId: Buffer,
    nodeId: string,
    peerId?: string,
  ): Promise<void> {
    const keyIdString = encodeKeyId(keyId);
    const privateKeyDer = await derSerializePrivateKey(privateKey);
    try {
      await this.saveSessionKeySerialized(keyIdString, privateKeyDer, nodeId, peerId);
    } catch (error) {
      throw new KeyStoreError(error as Error, `Failed to save key ${keyIdString}`);
    }
  }

  /**
   * Return the public key of the latest, unbound session key pair for the specified `nodeId`.
   *
   * @param nodeId The id of the node that owns the key
   * @throws PrivateKeyStoreError when the look-up could not be done
   * @return The public key if it exists or `null` otherwise
   */
  public async retrieveUnboundSessionPublicKey(nodeId: string): Promise<SessionKey | null> {
    const data = await this.retrieveLatestUnboundSessionKeyData(nodeId);

    if (!data) {
      return null;
    }

    const privateKey = await derDeserializeECDHPrivateKey(data.keySerialized);
    const publicKeySerialised = await derSerializePublicKey(privateKey);
    const publicKey = await derDeserializeECDHPublicKey(publicKeySerialised);
    return { keyId: decodeKeyId(data.keyId), publicKey };
  }

  /**
   * Return the latest unbound session key for the specified `nodeId`.
   *
   * @param nodeId The id of the node that owns the key
   */
  protected abstract retrieveLatestUnboundSessionKeyData(
    nodeId: string,
  ): Promise<UnboundSessionPrivateKeyData | null>;

  /**
   * Retrieve private session key, regardless of whether it's an initial key or not.
   *
   * @param keyId The key pair id (typically the serial number)
   * @param nodeId The id of the node that owns the key
   * @param peerId The id of the recipient, in case the key is bound to
   *    a recipient
   * @throws UnknownKeyError when the key does not exist
   * @throws PrivateKeyStoreError when the look-up could not be done
   */
  public async retrieveSessionKey(
    keyId: Buffer,
    nodeId: string,
    peerId: string,
  ): Promise<CryptoKey> {
    const keyData = await this.retrieveSessionKeyDataOrThrowError(keyId, nodeId);
    const keyIdHex = encodeKeyId(keyId);

    if (keyData.peerId && peerId !== keyData.peerId) {
      throw new UnknownKeyError(
        `Session key ${keyIdHex} is bound to another recipient ` +
          `(${keyData.peerId}, not ${peerId})`,
      );
    }

    return derDeserializeECDHPrivateKey(keyData.keySerialized, 'P-256');
  }

  //endregion

  public abstract saveIdentityKey(nodeId: string, privateKey: CryptoKey): Promise<void>;

  protected abstract saveSessionKeySerialized(
    keyId: string,
    keySerialized: Buffer,
    nodeId: string,
    peerId?: string,
  ): Promise<void>;
  protected abstract retrieveSessionKeyData(keyId: string): Promise<SessionPrivateKeyData | null>;

  private async retrieveSessionKeyDataOrThrowError(
    keyId: Buffer,
    nodeId: string,
  ): Promise<SessionPrivateKeyData> {
    const keyIdHex = encodeKeyId(keyId);
    let keyData: SessionPrivateKeyData | null;
    try {
      keyData = await this.retrieveSessionKeyData(keyIdHex);
    } catch (error) {
      throw new KeyStoreError(error as Error, `Failed to retrieve key`);
    }
    if (keyData === null) {
      throw new UnknownKeyError(`Key ${keyIdHex} does not exist`);
    }
    if (keyData.nodeId !== nodeId) {
      throw new UnknownKeyError('Key is owned by a different node');
    }
    return keyData;
  }

  protected async generateRSAKeyPair(
    keyOptions: Partial<RSAKeyGenOptions>,
  ): Promise<CryptoKeyPair> {
    return generateRSAKeyPair(keyOptions);
  }
}

function encodeKeyId(keyId: Buffer): string {
  return keyId.toString('hex');
}

function decodeKeyId(keyIdHex: string): Buffer {
  return Buffer.from(keyIdHex, 'hex');
}
