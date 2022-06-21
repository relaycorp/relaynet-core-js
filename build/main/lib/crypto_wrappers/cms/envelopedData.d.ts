/// <reference types="node" />
import { SessionKey } from '../../SessionKey';
import Certificate from '../x509/Certificate';
export interface EncryptionOptions {
    /** The AES key size (128, 192 or 256) */
    readonly aesKeySize: number;
}
/**
 * Result of producing an EnvelopedData value with the Channel Session Protocol.
 */
export interface SessionEncryptionResult {
    /** Id of ECDH key pair. */
    readonly dhKeyId: ArrayBuffer;
    /** Private key of the ECDH key pair */
    readonly dhPrivateKey: CryptoKey;
    /** EnvelopedData value using the Channel Session Protocol. */
    readonly envelopedData: SessionEnvelopedData;
}
export declare abstract class EnvelopedData {
    /**
     * Deserialize an EnvelopedData value into a `SessionlessEnvelopedData` or `SessionEnvelopedData`
     * instance.
     *
     * Depending on the type of RecipientInfo.
     *
     * @param envelopedDataSerialized
     */
    static deserialize(envelopedDataSerialized: ArrayBuffer): EnvelopedData;
    /**
     * Return the DER serialization of the current EnvelopedData value.
     *
     * It'll be wrapped around a `ContentInfo` value.
     */
    serialize(): ArrayBuffer;
    /**
     * Return the plaintext for the ciphertext contained in the current EnvelopedData value.
     *
     * @param privateKey The private key to decrypt the ciphertext.
     */
    decrypt(privateKey: CryptoKey): Promise<ArrayBuffer>;
    /**
     * Return the id of the recipient's key used to encrypt the content.
     *
     * This id will often be the recipient's certificate's serial number, in which case the issuer
     * will be ignored: This method is meant to be used by the recipient so it can look up the
     * corresponding private key to decrypt the content. We could certainly extract the issuer to
     * verify it matches the expected one, but if the id doesn't match any key decryption
     * won't even be attempted, so there's really no risk from ignoring the issuer.
     */
    abstract getRecipientKeyId(): Buffer;
}
/**
 * CMS EnvelopedData representation that doesn't use the Channel Session Protocol.
 *
 * Consequently, it uses the key transport choice (`KeyTransRecipientInfo`) from CMS.
 */
export declare class SessionlessEnvelopedData extends EnvelopedData {
    /**
     * Return an EnvelopedData value without using the Channel Session Protocol.
     *
     * @param plaintext The plaintext whose ciphertext has to be embedded in the EnvelopedData value.
     * @param certificate The certificate for the recipient.
     * @param options Any encryption options.
     */
    static encrypt(plaintext: ArrayBuffer, certificate: Certificate, options?: Partial<EncryptionOptions>): Promise<SessionlessEnvelopedData>;
    getRecipientKeyId(): Buffer;
}
/**
 * CMS EnvelopedData representation using the Channel Session Protocol.
 *
 * Consequently, it uses the key agreement (`KeyAgreeRecipientInfo`) from CMS.
 */
export declare class SessionEnvelopedData extends EnvelopedData {
    /**
     * Return an EnvelopedData value using the Channel Session Protocol.
     *
     * @param plaintext The plaintext whose ciphertext has to be embedded in the EnvelopedData value.
     * @param recipientSessionKey The ECDH public key of the recipient.
     * @param options Any encryption options.
     */
    static encrypt(plaintext: ArrayBuffer, recipientSessionKey: SessionKey, options?: Partial<EncryptionOptions>): Promise<SessionEncryptionResult>;
    /**
     * Return the key of the ECDH key of the originator/producer of the EnvelopedData value.
     */
    getOriginatorKey(): Promise<SessionKey>;
    getRecipientKeyId(): Buffer;
}
