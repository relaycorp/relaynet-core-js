import Certificate from '../../crypto_wrappers/x509/Certificate';
/**
 * Object to produce detached signatures given a key pair.
 */
export declare abstract class Signer {
    certificate: Certificate;
    private privateKey;
    abstract readonly oid: string;
    /**
     *
     * @param certificate The certificate of the node
     * @param privateKey The private key of the node
     */
    constructor(certificate: Certificate, privateKey: CryptoKey);
    sign(plaintext: ArrayBuffer): Promise<ArrayBuffer>;
}
