/** Key of the sender or recipient of the EnvelopedData value using the Channel Session Protocol */
export interface SessionKey {
  /** Id of the ECDH key pair */
  readonly keyId: Buffer;

  /** Public key of the ECDH key pair. */
  readonly publicKey: CryptoKey; // DH or ECDH key
}
