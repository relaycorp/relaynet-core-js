export interface IdentityKeyPair extends CryptoKeyPair {
  readonly privateAddress: string;
}
