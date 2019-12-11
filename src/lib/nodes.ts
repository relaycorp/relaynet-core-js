import { getPublicKeyDigest } from './crypto_wrappers/_utils';
import BaseCertificateOptions from './crypto_wrappers/x509/BaseCertificateOptions';
import Certificate from './crypto_wrappers/x509/Certificate';

export interface NodeCertificateOptions extends BaseCertificateOptions {}

export async function issueNodeCertificate(options: NodeCertificateOptions): Promise<Certificate> {
  const address = await computePrivateNodeAddress(options.subjectPublicKey);
  return Certificate.issue({ ...options, commonName: address });
}

async function computePrivateNodeAddress(publicKey: CryptoKey): Promise<string> {
  const publicKeyDigest = Buffer.from(await getPublicKeyDigest(publicKey));
  return `0${publicKeyDigest.toString('hex')}`;
}

export async function issueInitialDHKeyCertificate(
  dhPublicKey: CryptoKey,
  nodePrivateKey: CryptoKey,
  nodeCertificate: Certificate,
  serialNumber: number,
  validityEndDate: Date,
  validityStartDate?: Date,
): Promise<Certificate> {
  return Certificate.issue({
    commonName: nodeCertificate.getCommonName(),
    isCA: false,
    issuerCertificate: nodeCertificate,
    issuerPrivateKey: nodePrivateKey,
    serialNumber,
    subjectPublicKey: dhPublicKey,
    validityEndDate,
    validityStartDate: validityStartDate || new Date(),
  });
}
