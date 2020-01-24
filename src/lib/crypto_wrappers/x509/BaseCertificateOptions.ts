import Certificate from './Certificate';

export default interface BaseCertificateOptions {
  readonly isCA?: boolean;
  readonly issuerCertificate?: Certificate; // Absent when self-signed
  readonly issuerPrivateKey: CryptoKey;
  readonly subjectPublicKey: CryptoKey;
  readonly serialNumber?: number;
  readonly validityStartDate?: Date;
  readonly validityEndDate: Date;
}
