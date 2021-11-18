/** Key of the sender or recipient of the EnvelopedData value using the Channel Session Protocol */
export interface SessionKey {
  readonly keyId: Buffer;
  readonly publicKey: CryptoKey;
}
