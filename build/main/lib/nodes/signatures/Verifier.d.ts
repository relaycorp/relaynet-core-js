import Certificate from '../../crypto_wrappers/x509/Certificate';
/**
 * Object to verify detached signatures given a key pair.
 */
export declare abstract class Verifier {
    protected trustedCertificates: readonly Certificate[];
    abstract readonly oid: string;
    constructor(trustedCertificates: readonly Certificate[]);
    /**
     * Verify `signatureSerialized` and return the signer's certificate if valid.
     *
     * @param signatureSerialized
     * @param expectedPlaintext
     * @throws CMSError if the signatureSerialized is invalid
     * @throws CertificateError if the signer isn't trusted
     */
    verify(signatureSerialized: ArrayBuffer, expectedPlaintext: ArrayBuffer): Promise<Certificate>;
}
