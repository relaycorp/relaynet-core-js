/* tslint:disable:max-classes-per-file */

import {
  derDeserializeECDHPrivateKey,
  derDeserializeRSAPrivateKey,
  derSerializePrivateKey,
  getPrivateAddressFromIdentityKey,
} from '../crypto_wrappers/keys';
import RelaynetError from '../RelaynetError';
import UnknownKeyError from './UnknownKeyError';

/**
 * Data for a private key of a session key pair.
 */
export interface SessionPrivateKeyData {
  readonly keySerialized: Buffer;
  readonly peerPrivateAddress?: string;
}

/**
 * Error thrown when there was a failure in the communication with the backing service.
 */
export class PrivateKeyStoreError extends RelaynetError {}

export abstract class PrivateKeyStore {
  //region Identity keys

  /**
   * Save identity `privateKey`.
   *
   * @param privateKey
   * @return The corresponding private address
   */
  public async saveIdentityKey(privateKey: CryptoKey): Promise<string> {
    const privateAddress = await getPrivateAddressFromIdentityKey(privateKey);
    const privateKeyDer = await derSerializePrivateKey(privateKey);
    try {
      await this.saveIdentityKeySerialized(privateAddress, privateKeyDer);
    } catch (err) {
      throw new PrivateKeyStoreError(err as Error, `Failed to save key for ${privateAddress}`);
    }
    return privateAddress;
  }

  /**
   * Return the private component of a node key pair if it exists.
   *
   * @param privateAddress
   * @throws PrivateKeyStoreError when the look up could not be done
   */
  public async retrieveIdentityKey(privateAddress: string): Promise<CryptoKey | null> {
    let keySerialized: Buffer | null;
    try {
      keySerialized = await this.retrieveIdentityKeySerialized(privateAddress);
    } catch (err) {
      throw new PrivateKeyStoreError(err as Error, `Failed to retrieve key for ${privateAddress}`);
    }

    if (!keySerialized) {
      return null;
    }

    return derDeserializeRSAPrivateKey(keySerialized, {
      hash: { name: 'SHA-256' },
      name: 'RSA-PSS',
    });
  }

  //endregion
  //region Session keys

  public async saveUnboundSessionKey(privateKey: CryptoKey, keyId: Buffer): Promise<void> {
    await this.saveSessionKeyOrWrapError(keyId, privateKey);
  }

  public async saveBoundSessionKey(
    privateKey: CryptoKey,
    keyId: Buffer,
    peerPrivateAddress: string,
  ): Promise<void> {
    await this.saveSessionKeyOrWrapError(keyId, privateKey, peerPrivateAddress);
  }

  /**
   * Return the private component of an initial session key pair.
   *
   * @param keyId The key pair id (typically the serial number)
   * @throws UnknownKeyError when the key does not exist
   * @throws PrivateKeyStoreError when the look up could not be done
   */
  public async retrieveUnboundSessionKey(keyId: Buffer): Promise<CryptoKey> {
    const keyData = await this.retrieveSessionKeyDataOrThrowError(keyId);

    if (keyData.peerPrivateAddress) {
      throw new UnknownKeyError(`Key ${keyId.toString('hex')} is bound`);
    }

    return derDeserializeECDHPrivateKey(keyData.keySerialized, 'P-256');
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
  public async retrieveSessionKey(keyId: Buffer, peerPrivateAddress: string): Promise<CryptoKey> {
    const keyData = await this.retrieveSessionKeyDataOrThrowError(keyId);
    const keyIdHex = keyId.toString('hex');

    if (keyData.peerPrivateAddress && peerPrivateAddress !== keyData.peerPrivateAddress) {
      throw new UnknownKeyError(
        `Session key ${keyIdHex} is bound to another recipient ` +
          `(${keyData.peerPrivateAddress}, not ${peerPrivateAddress})`,
      );
    }

    return derDeserializeECDHPrivateKey(keyData.keySerialized, 'P-256');
  }

  //endregion

  protected abstract retrieveIdentityKeySerialized(privateAddress: string): Promise<Buffer | null>;
  protected abstract retrieveSessionKeyData(keyId: string): Promise<SessionPrivateKeyData | null>;

  protected abstract saveIdentityKeySerialized(
    privateAddress: string,
    keySerialized: Buffer,
  ): Promise<void>;
  protected abstract saveSessionKeySerialized(
    keyId: string,
    keySerialized: Buffer,
    peerPrivateAddress?: string,
  ): Promise<void>;

  private async retrieveSessionKeyDataOrThrowError(keyId: Buffer): Promise<SessionPrivateKeyData> {
    const keyIdHex = keyId.toString('hex');
    let key: SessionPrivateKeyData | null;
    try {
      key = await this.retrieveSessionKeyData(keyIdHex);
    } catch (error) {
      throw new PrivateKeyStoreError(error as Error, `Failed to retrieve key`);
    }
    if (key === null) {
      throw new UnknownKeyError(`Key ${keyIdHex} does not exist`);
    }
    return key;
  }

  private async saveSessionKeyOrWrapError(
    keyId: Buffer,
    privateKey: CryptoKey,
    peerPrivateAddress?: string,
  ): Promise<void> {
    const keyIdString = keyId.toString('hex');
    const privateKeyDer = await derSerializePrivateKey(privateKey);
    try {
      await this.saveSessionKeySerialized(keyIdString, privateKeyDer, peerPrivateAddress);
    } catch (error) {
      throw new PrivateKeyStoreError(error as Error, `Failed to save key ${keyIdString}`);
    }
  }
}
