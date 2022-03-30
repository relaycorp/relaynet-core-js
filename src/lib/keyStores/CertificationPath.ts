import Certificate from '../crypto_wrappers/x509/Certificate';

export interface CertificationPath {
  readonly leafCertificate: Certificate;
  readonly chain: readonly Certificate[];
}
