/// <reference types="node" />
import { RSAKeyGenOptions } from '../crypto_wrappers/keys';
import { IdentityKeyPair } from '../IdentityKeyPair';
/**
 * Data for a private key of a session key pair.
 */
export interface SessionPrivateKeyData {
    readonly keySerialized: Buffer;
    readonly privateAddress: string;
    readonly peerPrivateAddress?: string;
}
export declare abstract class PrivateKeyStore {
    generateIdentityKeyPair(keyOptions?: Partial<RSAKeyGenOptions>): Promise<IdentityKeyPair>;
    /**
     * Return the private component of a node key pair if it exists.
     *
     * @param privateAddress
     * @throws {KeyStoreError} if the backend failed to retrieve the key due to an error
     */
    abstract retrieveIdentityKey(privateAddress: string): Promise<CryptoKey | null>;
    saveSessionKey(privateKey: CryptoKey, keyId: Buffer, privateAddress: string, peerPrivateAddress?: string): Promise<void>;
    /**
     * Return the private component of an initial session key pair.
     *
     * @param keyId The key pair id (typically the serial number)
     * @param privateAddress The private address of the node that owns the key
     * @throws UnknownKeyError when the key does not exist
     * @throws PrivateKeyStoreError when the look up could not be done
     */
    retrieveUnboundSessionKey(keyId: Buffer, privateAddress: string): Promise<CryptoKey>;
    /**
     * Retrieve private session key, regardless of whether it's an initial key or not.
     *
     * @param keyId The key pair id (typically the serial number)
     * @param privateAddress The private address of the node that owns the key
     * @param peerPrivateAddress The private address of the recipient, in case the key is bound to
     *    a recipient
     * @throws UnknownKeyError when the key does not exist
     * @throws PrivateKeyStoreError when the look up could not be done
     */
    retrieveSessionKey(keyId: Buffer, privateAddress: string, peerPrivateAddress: string): Promise<CryptoKey>;
    protected abstract saveIdentityKey(privateAddress: string, privateKey: CryptoKey): Promise<void>;
    protected abstract saveSessionKeySerialized(keyId: string, keySerialized: Buffer, privateAddress: string, peerPrivateAddress?: string): Promise<void>;
    protected abstract retrieveSessionKeyData(keyId: string): Promise<SessionPrivateKeyData | null>;
    private retrieveSessionKeyDataOrThrowError;
    protected generateRSAKeyPair(keyOptions: Partial<RSAKeyGenOptions>): Promise<CryptoKeyPair>;
}
