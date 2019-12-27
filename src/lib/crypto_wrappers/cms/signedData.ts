// tslint:disable:no-object-mutation
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

import * as oids from '../../oids';
import { getPkijsCrypto } from '../_utils';
import Certificate from '../x509/Certificate';
import { deserializeContentInfo } from './_utils';
import CMSError from './CMSError';

const pkijsCrypto = getPkijsCrypto();

export interface SignatureVerification {
  readonly signerCertificate: Certificate;
  readonly signerCertificateChain: ReadonlyArray<Certificate>;
}

export interface SignatureOptions {
  readonly hashingAlgorithmName: string;
}

/**
 * Generate DER-encoded CMS SignedData signature for `plaintext`.
 *
 * @param plaintext
 * @param privateKey
 * @param signerCertificate
 * @param attachedCertificates
 * @param options
 * @throws `CMSError` when attempting to use SHA-1 as the hashing function
 */
export async function sign(
  plaintext: ArrayBuffer,
  privateKey: CryptoKey,
  signerCertificate: Certificate,
  attachedCertificates: ReadonlySet<Certificate> = new Set(),
  options: Partial<SignatureOptions> = {},
): Promise<ArrayBuffer> {
  // RS-018 prohibits the use of MD5 and SHA-1, but WebCrypto doesn't support MD5
  if (options.hashingAlgorithmName === 'SHA-1') {
    throw new CMSError('SHA-1 is disallowed by RS-018');
  }

  const hashingAlgorithmName = options.hashingAlgorithmName || 'SHA-256';
  const digest = await pkijsCrypto.digest({ name: hashingAlgorithmName }, plaintext);
  const signerInfo = initSignerInfo(signerCertificate, digest);
  const signedData = new pkijs.SignedData({
    certificates: Array.from(attachedCertificates).map(c => c.pkijsCertificate),
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: oids.CMS_DATA,
    }),
    signerInfos: [signerInfo],
    version: 1,
  });
  await signedData.sign(privateKey, 0, hashingAlgorithmName);

  const contentInfo = new pkijs.ContentInfo({
    content: signedData.toSchema(true),
    contentType: oids.CMS_SIGNED_DATA,
  });
  return contentInfo.toSchema().toBER(false);
}

function initSignerInfo(signerCertificate: Certificate, digest: ArrayBuffer): pkijs.SignerInfo {
  const signerIdentifier = new pkijs.IssuerAndSerialNumber({
    issuer: signerCertificate.pkijsCertificate.issuer,
    serialNumber: signerCertificate.pkijsCertificate.serialNumber,
  });
  const contentTypeAttribute = new pkijs.Attribute({
    type: oids.CMS_ATTR_CONTENT_TYPE,
    values: [new asn1js.ObjectIdentifier({ value: oids.CMS_DATA })],
  });
  const digestAttribute = new pkijs.Attribute({
    type: oids.CMS_ATTR_DIGEST,
    values: [new asn1js.OctetString({ valueHex: digest })],
  });
  return new pkijs.SignerInfo({
    sid: signerIdentifier,
    signedAttrs: new pkijs.SignedAndUnsignedAttributes({
      attributes: [contentTypeAttribute, digestAttribute],
      type: 0,
    }),
    version: 1,
  });
}

/**
 * Verify CMS SignedData signature.
 *
 * @param signature The CMS SignedData signature, DER-encoded.
 * @param plaintext The plaintext to be verified against signature.
 * @param detachedSignerCertificateOrTrustedCertificates Either the signer's certificate when
 *   detached from the SignedData or the set of trusted CAs.
 * @throws {CMSError} If `signature` could not be decoded or verified.
 */
export async function verifySignature(
  signature: ArrayBuffer,
  plaintext: ArrayBuffer,
  detachedSignerCertificateOrTrustedCertificates?: Certificate | ReadonlyArray<Certificate>,
): Promise<SignatureVerification> {
  const detachedSignerCertificate =
    detachedSignerCertificateOrTrustedCertificates instanceof Certificate
      ? detachedSignerCertificateOrTrustedCertificates
      : undefined;
  const trustedCertificates =
    detachedSignerCertificateOrTrustedCertificates instanceof Array
      ? detachedSignerCertificateOrTrustedCertificates
      : undefined;

  const contentInfo = deserializeContentInfo(signature);

  const signedData = new pkijs.SignedData({ schema: contentInfo });
  if (detachedSignerCertificate) {
    signedData.certificates = [detachedSignerCertificate.pkijsCertificate];
  } else if (trustedCertificates) {
    const originalCertificates = signedData.certificates as ReadonlyArray<pkijs.Certificate>;
    signedData.certificates = [
      ...originalCertificates,
      ...trustedCertificates.map(c => c.pkijsCertificate),
    ];
  }

  // tslint:disable-next-line:no-let
  let verificationResult;
  try {
    verificationResult = await signedData.verify({
      checkChain: !!trustedCertificates,
      data: plaintext,
      extendedMode: true,
      signer: 0,
      trustedCerts: trustedCertificates
        ? trustedCertificates.map(c => c.pkijsCertificate)
        : undefined,
    });

    if (!verificationResult.signatureVerified) {
      throw verificationResult;
    }
  } catch (e) {
    throw new CMSError(`Invalid signature: ${e.message} (PKI.js code: ${e.code})`);
  }

  const pkijsCertificateChain = trustedCertificates
    ? ((verificationResult as unknown) as MissingSignedDataVerifyResult).certificatePath
    : [((verificationResult as unknown) as MissingSignedDataVerifyResult).signerCertificate];
  return {
    signerCertificate: new Certificate(verificationResult.signerCertificate as pkijs.Certificate),
    signerCertificateChain: pkijsCertificateChain.map(c => new Certificate(c)),
  };
}

/**
 * Attributes missing from the typing for `VerifyResult` in PKI.js
 *
 * TODO: Create PR for @types/pkijs
 */
interface MissingSignedDataVerifyResult {
  readonly certificatePath: ReadonlyArray<pkijs.Certificate>;
  readonly signerCertificate: pkijs.Certificate;
}
