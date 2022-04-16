import Certificate from '../crypto_wrappers/x509/Certificate';

export class CertificationPath {
  constructor(
    public readonly leafCertificate: Certificate,
    public readonly certificateAuthorities: readonly Certificate[],
  ) {}
}
