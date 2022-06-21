/**
 * Plain RSA signatures are used when CMS SignedData can't be used. That is, when the signer
 * doesn't (yet) have a certificate.
 */
export declare function sign(plaintext: ArrayBuffer, privateKey: CryptoKey): Promise<ArrayBuffer>;
export declare function verify(signature: ArrayBuffer, publicKey: CryptoKey, expectedPlaintext: ArrayBuffer): Promise<boolean>;
