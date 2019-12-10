import BaseCertificateOptions from './BaseCertificateOptions';

export default interface CertificateOptions extends BaseCertificateOptions {
  readonly commonName: string;
}
