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
  const envelopedData = new pkijs.EnvelopedData();

  envelopedData.addRecipientByCertificate(
    certificate.pkijsCertificate,
    { oaepHashAlgorithm: 'SHA-256' },
    1
  );

  if (options.aesKeySize && !AES_KEY_SIZES.includes(options.aesKeySize)) {
    throw new CMSError(`Invalid AES key size (${options.aesKeySize})`);
  }

  const aesKeySize = options.aesKeySize || 128;
  await envelopedData.encrypt(
    // @ts-ignore
    { name: 'AES-GCM', length: aesKeySize },
    plaintext
  );

  const contentInfo = new pkijs.ContentInfo({
    content: envelopedData.toSchema(),
    contentType: oids.CMS_ENVELOPED_DATA
  });
  return contentInfo.toSchema().toBER(false);
}

/**
 * Decrypt `ciphertext` and return plaintext.
 *
 * @param ciphertext DER-encoded CMS EnvelopedData
 * @param privateKey
 * @throws CMSError if `ciphertext` is malformed or could not be decrypted
 *   with `privateKey`
 */
export async function decrypt(
  ciphertext: ArrayBuffer,
  privateKey: CryptoKey
): Promise<ArrayBuffer> {
  const cmsContentInfo = deserializeContentInfo(ciphertext);
  const cmsEnvelopedSimp = new pkijs.EnvelopedData({ schema: cmsContentInfo });

  const privateKeyBuffer = await pkijsCrypto.exportKey('pkcs8', privateKey);
  try {
    return await cmsEnvelopedSimp.decrypt(
      0,
      // @ts-ignore
      { recipientPrivateKey: privateKeyBuffer }
    );
  } catch (error) {
    throw new CMSError(`Decryption failed: ${error}`);
  }
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
  options: Partial<SignatureOptions> = {}
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
      eContentType: oids.CMS_DATA
    }),
    signerInfos: [signerInfo],
    version: 1
  });
  await signedData.sign(privateKey, 0, hashingAlgorithmName);

  const contentInfo = new pkijs.ContentInfo({
    content: signedData.toSchema(true),
    contentType: oids.CMS_SIGNED_DATA
  });
  return contentInfo.toSchema().toBER(false);
}

function initSignerInfo(signerCertificate: Certificate, digest: ArrayBuffer): pkijs.SignerInfo {
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
 * @return Certificates attached to `signature` unless `signerCertificate` is
 *   passed.
 * @throws {CMSError} If `signature` could not be decoded or verified.
 */
export async function verifySignature(
  signature: ArrayBuffer,
  plaintext: ArrayBuffer,
  signerCertificate?: Certificate
): Promise<ReadonlyArray<Certificate> | undefined> {
  const contentInfo = deserializeContentInfo(signature);

  const signedData = new pkijs.SignedData({ schema: contentInfo });
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
    throw new CMSError(`Invalid signature: "${e.message}" (PKI.js code: ${e.code})`);
  }

  if (!signerCertificate) {
    // @ts-ignore
    return signedData.certificates.map(c => new Certificate(c));
  }
  return;
}

function deserializeContentInfo(derValue: ArrayBuffer): asn1js.Sequence {
  const asn1 = asn1js.fromBER(derValue);
  if (asn1.offset === -1) {
    throw new CMSError('Value is not encoded in DER');
  }
  const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
  return contentInfo.content;
}
