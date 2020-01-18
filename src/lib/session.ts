/**
 * Interface to save and retrieve channel session keys.
 */
export interface SessionStore {
  readonly getPrivateKey: (
    dhKeyPairId: number,
    recipientPublicKey: CryptoKey,
  ) => Promise<CryptoKey>;

  readonly savePrivateKey: (
    dhPrivateKey: CryptoKey,
    dhKeyPairId: number,
    recipientPublicKey: CryptoKey,
  ) => Promise<void>;
}
