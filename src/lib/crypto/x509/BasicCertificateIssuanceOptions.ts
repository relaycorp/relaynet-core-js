export interface BasicCertificateIssuanceOptions {
  readonly issuerPrivateKey: CryptoKey;
  readonly subjectPublicKey: CryptoKey;
  readonly validityStartDate?: Date;
  readonly validityEndDate: Date;
}
