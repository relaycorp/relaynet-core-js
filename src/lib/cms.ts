import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { getPkijsCrypto } from './_utils';
import CMSError from './CMSError';
import * as oids from './oids';
import Certificate from './pki/Certificate';

const pkijsCrypto = getPkijsCrypto();

const AES_KEY_SIZES: ReadonlyArray<number> = [128, 192, 256];

export interface EncryptionOptions {
  readonly aesKeySize: number;
}

/**
 * Encrypt `plaintext` and return DER-encoded CMS EnvelopedData representation.
 *
 * @param plaintext
 * @param certificate
 * @param options
 */
export async function encrypt(
  plaintext: ArrayBuffer,
  certificate: Certificate,
  options: Partial<EncryptionOptions> = {}
): Promise<ArrayBuffer> {
  const cmsEnveloped = new pkijs.EnvelopedData();

  cmsEnveloped.addRecipientByCertificate(certificate.pkijsCertificate, {}, 1);

  if (options.aesKeySize && !AES_KEY_SIZES.includes(options.aesKeySize)) {
    throw new CMSError(`Invalid AES key size (${options.aesKeySize})`);
  }

  const aesKeySize = options.aesKeySize || 128;
  await cmsEnveloped.encrypt(
    // @ts-ignore
    { name: 'AES-GCM', length: aesKeySize },
    plaintext
  );

  const contentInfo = new pkijs.ContentInfo({
    content: cmsEnveloped.toSchema(),
    contentType: oids.CMS_ENVELOPED_DATA
  });
  return contentInfo.toSchema().toBER(false);
}

/**
 * Generate DER-encoded CMS SignedData signature for `plaintext`.
 *
 * @param plaintext
 * @param privateKey
 * @param signerCertificate
 * @param embeddedCertificates
 * @param hashingAlgorithmName
 * @throws {CMSError} If attempting to use SHA-1 as the hashing function
 */
export async function sign(
  plaintext: ArrayBuffer,
  privateKey: CryptoKey,
  signerCertificate: Certificate,
  embeddedCertificates: ReadonlyArray<Certificate> = [],
  hashingAlgorithmName = 'SHA-256'
): Promise<ArrayBuffer> {
  // RS-018 prohibits the use of MD5 and SHA-1, but WebCrypto doesn't support MD5
  if (hashingAlgorithmName === 'SHA-1') {
    throw new CMSError('SHA-1 is disallowed by RS-018');
  }

  const digest = await pkijsCrypto.digest(
    { name: hashingAlgorithmName },
    plaintext
  );
  const signerInfo = initSignerInfo(signerCertificate, digest);
  const cmsSigned = new pkijs.SignedData({
    certificates: embeddedCertificates.map(c => c.pkijsCertificate),
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: oids.CMS_DATA
    }),
    signerInfos: [signerInfo],
    version: 1
  });
  await cmsSigned.sign(privateKey, 0, hashingAlgorithmName, plaintext);

  const contentInfo = new pkijs.ContentInfo({
    content: cmsSigned.toSchema(true),
    contentType: oids.CMS_SIGNED_DATA
  });
  return contentInfo.toSchema().toBER(false);
}

function initSignerInfo(
  signerCertificate: Certificate,
  digest: ArrayBuffer
): pkijs.SignerInfo {
  const signerIdentifier = new pkijs.IssuerAndSerialNumber({
    issuer: signerCertificate.pkijsCertificate.issuer,
    serialNumber: signerCertificate.pkijsCertificate.serialNumber
  });
  const contentTypeAttribute = new pkijs.Attribute({
    type: oids.CMS_ATTR_CONTENT_TYPE,
    values: [new asn1js.ObjectIdentifier({ value: oids.CMS_DATA })]
  });
  const digestAttribute = new pkijs.Attribute({
    type: oids.CMS_ATTR_DIGEST,
    values: [new asn1js.OctetString({ valueHex: digest })]
  });
  return new pkijs.SignerInfo({
    sid: signerIdentifier,
    signedAttrs: new pkijs.SignedAndUnsignedAttributes({
      attributes: [contentTypeAttribute, digestAttribute],
      type: 0
    }),
    version: 1
  });
}

/**
 * Verify CMS SignedData signature.
 *
 * @param signature The CMS SignedData signature, DER-encoded.
 * @param plaintext The plaintext to be verified against signature.
 * @param signerCertificate The expected signer certificate.
 * @return Certificates embedded in `signature` unless signerCertificate is
 *   passed.
 */
export async function verifySignature(
  signature: ArrayBuffer,
  plaintext: ArrayBuffer,
  signerCertificate?: Certificate
): Promise<ReadonlyArray<Certificate> | undefined> {
  const asn1 = asn1js.fromBER(signature);
  if (asn1.offset === -1) {
    throw new CMSError('Signature is not DER-encoded');
  }
  const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });

  const signedData = new pkijs.SignedData({ schema: contentInfo.content });
  if (signerCertificate) {
    // tslint:disable-next-line
    signedData.certificates = [signerCertificate.pkijsCertificate];
  }

  try {
    const verificationResult = await signedData.verify({
      data: plaintext,
      extendedMode: true,
      signer: 0
    });

    if (!verificationResult.signatureVerified) {
      throw verificationResult;
    }
  } catch (e) {
    throw new CMSError(
      `Invalid signature: "${e.message}" (PKI.js code: ${e.code})`
    );
  }

  if (!signerCertificate) {
    // @ts-ignore
    return signedData.certificates.map(c => new Certificate(c));
  }
  return;
}
