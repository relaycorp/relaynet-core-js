export default interface BasicCertificateIssuanceOptions {
  readonly issuerPrivateKey: CryptoKey;
  readonly subjectPublicKey: CryptoKey;
  readonly serialNumber?: number;
  readonly validityStartDate?: Date;
  readonly validityEndDate: Date;
}
