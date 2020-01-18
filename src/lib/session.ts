/**
 * Interface to save and retrieve channel session keys.
 */
export interface SessionStore {
  readonly getPrivateKey: (
    dhPrivateKeyId: number,
    recipientPublicKey: CryptoKey,
  ) => Promise<CryptoKey>;

  readonly savePrivateKey: (
    dhPrivateKey: CryptoKey,
    dhPrivateKeyId: number,
    recipientPublicKey: CryptoKey,
  ) => Promise<void>;
}
