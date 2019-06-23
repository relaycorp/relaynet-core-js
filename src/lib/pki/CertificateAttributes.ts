export default interface CertificateAttributes {
  readonly subjectPublicKey: CryptoKey;
  readonly serialNumber: number;
  readonly validityStartDate?: Date;
  readonly validityEndDate: Date;
}
