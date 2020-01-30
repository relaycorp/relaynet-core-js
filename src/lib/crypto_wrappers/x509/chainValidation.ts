import { CertificateChainValidationEngine } from 'pkijs';

import RelaynetError from '../../RelaynetError';
import Certificate from './Certificate';

export class UntrustedCertificateError extends RelaynetError {}

export async function validateCertificateTrust(
  certificate: Certificate,
  intermediateCaCertificates: readonly Certificate[],
  trustedCertificates: readonly Certificate[],
): Promise<void> {
  const chainValidator = new CertificateChainValidationEngine({
    certs: [
      ...intermediateCaCertificates.map(c => c.pkijsCertificate),
      certificate.pkijsCertificate,
    ],
    trustedCerts: trustedCertificates.map(c => c.pkijsCertificate),
  });
  const verification = await chainValidator.verify({ passedWhenNotRevValues: false });

  if (!verification.result) {
    throw new UntrustedCertificateError(verification.resultMessage);
  }
}
