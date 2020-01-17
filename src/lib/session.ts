export interface SessionStore {
  readonly getPrivateKey: (keyId: number, recipientAddress: string) => Promise<CryptoKey>;

  readonly savePrivateKey: (
    key: CryptoKey,
    keyId: number,
    recipientAddress: string,
  ) => Promise<void>;
}
