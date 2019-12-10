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
