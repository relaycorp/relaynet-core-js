import BasicCertificateIssuanceOptions from './BasicCertificateIssuanceOptions';
import Certificate from './Certificate';

export default interface FullCertificateIssuanceOptions extends BasicCertificateIssuanceOptions {
  readonly isCA?: boolean; // Basic Constraints extension
  readonly commonName: string;
  readonly issuerCertificate?: Certificate; // Absent when self-signed
  readonly pathLenConstraint?: number; // Basic Constraints extension
}
