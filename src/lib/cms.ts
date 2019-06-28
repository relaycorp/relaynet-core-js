import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { getPkijsCrypto } from './_utils';
import CMSError from './CMSError';
import * as oids from './oids';
import Certificate from './pki/Certificate';

const pkijsCrypto = getPkijsCrypto();

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

export async function verifySignature(
  signature: ArrayBuffer,
  plaintext: ArrayBuffer
): Promise<void> {
  const asn1 = asn1js.fromBER(signature);
  if (asn1.offset === -1) {
    throw new CMSError('Signature is not DER-encoded');
  }
  const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });

  const signedData = new pkijs.SignedData({
    schema: contentInfo.content
  });

  const { signatureVerified, code } = await signedData.verify({
    data: plaintext,
    extendedMode: true,
    signer: 0
  });

  if (!signatureVerified) {
    throw new CMSError(`Invalid signature (code: ${code})`);
  }
  return;
}
