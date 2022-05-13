/* tslint:disable:max-classes-per-file */

import {
  derDeserializeECDHPrivateKey,
  derSerializePrivateKey,
  generateRSAKeyPair,
  getPrivateAddressFromIdentityKey,
  RSAKeyGenOptions,
} from '../crypto_wrappers/keys';
import { IdentityKeyPair } from '../IdentityKeyPair';
import { KeyStoreError } from './KeyStoreError';
import UnknownKeyError from './UnknownKeyError';

/**
 * Data for a private key of a session key pair.
 */
export interface SessionPrivateKeyData {
  readonly keySerialized: Buffer;
  readonly peerPrivateAddress?: string;
}

export abstract class PrivateKeyStore {
  //region Identity keys

  public async generateIdentityKeyPair(
    keyOptions: Partial<RSAKeyGenOptions> = {},
  ): Promise<IdentityKeyPair> {
    const keyPair = await this.generateRSAKeyPair(keyOptions);
    const privateAddress = await getPrivateAddressFromIdentityKey(keyPair.publicKey);
    try {
      await this.saveIdentityKey(privateAddress, keyPair.privateKey);
    } catch (err) {
      throw new KeyStoreError(err as Error, `Failed to save key for ${privateAddress}`);
    }
    return { ...keyPair, privateAddress };
  }

  /**
   * Return the private component of a node key pair if it exists.
   *
   * @param privateAddress
   */
  public abstract retrieveIdentityKey(privateAddress: string): Promise<CryptoKey | null>;

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

  protected abstract saveIdentityKey(privateAddress: string, privateKey: CryptoKey): Promise<void>;

  protected abstract saveSessionKeySerialized(
    keyId: string,
    keySerialized: Buffer,
    peerPrivateAddress?: string,
  ): Promise<void>;
  protected abstract retrieveSessionKeyData(keyId: string): Promise<SessionPrivateKeyData | null>;

  private async retrieveSessionKeyDataOrThrowError(keyId: Buffer): Promise<SessionPrivateKeyData> {
    const keyIdHex = keyId.toString('hex');
    let key: SessionPrivateKeyData | null;
    try {
      key = await this.retrieveSessionKeyData(keyIdHex);
    } catch (error) {
      throw new KeyStoreError(error as Error, `Failed to retrieve key`);
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
      throw new KeyStoreError(error as Error, `Failed to save key ${keyIdString}`);
    }
  }

  protected async generateRSAKeyPair(
    keyOptions: Partial<RSAKeyGenOptions>,
  ): Promise<CryptoKeyPair> {
    return generateRSAKeyPair(keyOptions);
  }
}
