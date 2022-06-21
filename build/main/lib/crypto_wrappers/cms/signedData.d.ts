import * as pkijs from 'pkijs';
import Certificate from '../x509/Certificate';
import { SignatureOptions } from './SignatureOptions';
export interface SignatureVerification {
    readonly plaintext: ArrayBuffer;
    readonly signerCertificate: Certificate;
    readonly attachedCertificates: readonly Certificate[];
}
interface SignedDataOptions extends SignatureOptions {
    readonly encapsulatePlaintext: boolean;
}
export declare class SignedData {
    readonly pkijsSignedData: pkijs.SignedData;
    /**
     * The signed plaintext, if it was encapsulated.
     *
     * TODO: Cache output because computation can be relatively expensive
     */
    get plaintext(): ArrayBuffer | null;
    /**
     * The signer's certificate, if it was encapsulated.
     */
    get signerCertificate(): Certificate | null;
    /**
     * Set of encapsulated certificates.
     */
    get certificates(): Set<Certificate>;
    static sign(plaintext: ArrayBuffer, privateKey: CryptoKey, signerCertificate: Certificate, caCertificates?: readonly Certificate[], options?: Partial<SignedDataOptions>): Promise<SignedData>;
    static deserialize(signedDataSerialized: ArrayBuffer): SignedData;
    /**
     *
     * @param pkijsSignedData
     * @private
     */
    private static reDeserialize;
    constructor(pkijsSignedData: pkijs.SignedData);
    serialize(): ArrayBuffer;
    verify(expectedPlaintext?: ArrayBuffer): Promise<void>;
}
/**
 * Generate DER-encoded CMS SignedData signature for `plaintext`.
 *
 * TODO: REMOVE
 *
 * @param plaintext
 * @param privateKey
 * @param signerCertificate
 * @param caCertificates
 * @param options
 * @throws `CMSError` when attempting to use SHA-1 as the hashing function
 */
export declare function sign(plaintext: ArrayBuffer, privateKey: CryptoKey, signerCertificate: Certificate, caCertificates?: readonly Certificate[], options?: Partial<SignatureOptions>): Promise<ArrayBuffer>;
/**
 * Verify CMS SignedData `signature`.
 *
 * The CMS SignedData value must have the signer's certificate attached. CA certificates may
 * also be attached.
 *
 * @param cmsSignedDataSerialized The CMS SignedData signature, DER-encoded.
 * @return Signer's certificate chain, starting with the signer's certificate
 * @throws {CMSError} If `signature` could not be decoded or verified.
 *
 * TODO: Remove
 */
export declare function verifySignature(cmsSignedDataSerialized: ArrayBuffer): Promise<SignatureVerification>;
export {};
