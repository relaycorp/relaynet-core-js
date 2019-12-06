export default interface CertificateOptions {
  readonly isCA?: boolean;
  readonly subjectPublicKey: CryptoKey;
  readonly serialNumber: number;
  readonly validityStartDate?: Date;
  readonly validityEndDate: Date;
}
