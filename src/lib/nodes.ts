import { getPublicKeyDigest } from './crypto_wrappers/_utils';
import BaseCertificateOptions from './crypto_wrappers/x509/BaseCertificateOptions';
import Certificate from './crypto_wrappers/x509/Certificate';
import CertificateError from './crypto_wrappers/x509/CertificateError';

const MAX_DH_CERT_LENGTH_DAYS = 60;
const SECONDS_PER_DAY = 86_400;
const MAX_DH_CERT_LENGTH_MS = MAX_DH_CERT_LENGTH_DAYS * SECONDS_PER_DAY * 1_000;

const DEFAULT_DH_CERT_LENGTH_DAYS = 30;

export interface NodeCertificateOptions extends BaseCertificateOptions {}

export async function issueNodeCertificate(options: NodeCertificateOptions): Promise<Certificate> {
  const address = await computePrivateNodeAddress(options.subjectPublicKey);
  return Certificate.issue({ ...options, commonName: address });
}

async function computePrivateNodeAddress(publicKey: CryptoKey): Promise<string> {
  const publicKeyDigest = Buffer.from(await getPublicKeyDigest(publicKey));
  return `0${publicKeyDigest.toString('hex')}`;
}

export class DHCertificateError extends CertificateError {}

export async function issueInitialDHKeyCertificate(
  dhPublicKey: CryptoKey,
  nodePrivateKey: CryptoKey,
  nodeCertificate: Certificate,
  serialNumber: number,
  validityEndDate?: Date,
  validityStartDate?: Date,
): Promise<Certificate> {
  const startDate = validityStartDate || new Date();
  const endDate = validityEndDate || getDateAfterDays(startDate, DEFAULT_DH_CERT_LENGTH_DAYS);

  const certValidityLengthMs = endDate.getTime() - startDate.getTime();
  if (MAX_DH_CERT_LENGTH_MS < certValidityLengthMs) {
    throw new DHCertificateError(
      `DH key may not be valid for more than ${MAX_DH_CERT_LENGTH_DAYS} days`,
    );
  }

  return Certificate.issue({
    commonName: nodeCertificate.getCommonName(),
    isCA: false,
    issuerCertificate: nodeCertificate,
    issuerPrivateKey: nodePrivateKey,
    serialNumber,
    subjectPublicKey: dhPublicKey,
    validityEndDate: endDate,
    validityStartDate: startDate,
  });
}

function getDateAfterDays(initialDate: Date, additionalDays: number): Date {
  const newDate = new Date(initialDate);
  newDate.setDate(initialDate.getDate() + additionalDays);
  return newDate;
}
