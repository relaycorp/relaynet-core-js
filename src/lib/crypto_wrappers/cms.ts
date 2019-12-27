// tslint:disable:no-object-mutation
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

import * as oids from '../oids';
import { deserializeDer, getPkijsCrypto } from './_utils';
import CMSError from './CMSError';
import Certificate from './x509/Certificate';

const pkijsCrypto = getPkijsCrypto();

const AES_KEY_SIZES: ReadonlyArray<number> = [128, 192, 256];

export interface EncryptionOptions {
  readonly aesKeySize: number;
}
export interface EncryptionResult {
  readonly dhKeyId?: number;
  readonly dhPrivateKey?: CryptoKey; // DH or ECDH key
  readonly envelopedDataSerialized: ArrayBuffer;
}

export interface DecryptionResult {
  readonly dhKeyId?: number;
  readonly dhPublicKeyDer?: ArrayBuffer; // DH or ECDH key
  readonly plaintext: ArrayBuffer;
}

export interface SignatureVerification {
  readonly signerCertificate: Certificate;
  readonly signerCertificateChain: ReadonlyArray<Certificate>;
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
  options: Partial<EncryptionOptions> = {},
): Promise<EncryptionResult> {
  const envelopedData = new pkijs.EnvelopedData();

  envelopedData.addRecipientByCertificate(
    certificate.pkijsCertificate,
    { oaepHashAlgorithm: 'SHA-256' },
    1,
  );

  if (options.aesKeySize && !AES_KEY_SIZES.includes(options.aesKeySize)) {
    throw new CMSError(`Invalid AES key size (${options.aesKeySize})`);
  }

  const aesKeySize = options.aesKeySize || 128;
  const [pkijsEncryptionResult] = await envelopedData.encrypt(
    // @ts-ignore
    { name: 'AES-GCM', length: aesKeySize },
    plaintext,
  );
  const dhPrivateKey = pkijsEncryptionResult?.ecdhPrivateKey;

  // tslint:disable-next-line:no-let
  let dhKeyId : number | undefined;
  if (dhPrivateKey) {
    // `certificate` contains an (EC)DH public key, so EnvelopedData.encrypt() did a DH exchange.

    // Generate id for generated (EC)DH key and attach it to unprotectedAttrs per RS-003:
    dhKeyId = generateRandom32BitUnsignedNumber();
    const serialNumberAttribute = new pkijs.Attribute({
      type: oids.RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
      values: [new asn1js.Integer({ value: dhKeyId })],
    });
    envelopedData.unprotectedAttrs = [serialNumberAttribute];

    // EnvelopedData.encrypt() would've deleted the algorithm params so we should reinstate them:
    envelopedData.recipientInfos[0].value.originator.value.algorithm.algorithmParams =
      certificate.pkijsCertificate.subjectPublicKeyInfo.algorithm.algorithmParams;
  }

  const contentInfo = new pkijs.ContentInfo({
    content: envelopedData.toSchema(),
    contentType: oids.CMS_ENVELOPED_DATA,
  });
  const envelopedDataSerialized = contentInfo.toSchema().toBER(false);
  return { dhPrivateKey, dhKeyId, envelopedDataSerialized };
}

/**
 * Decrypt `ciphertext` and return plaintext.
 *
 * @param ciphertext DER-encoded CMS EnvelopedData
 * @param privateKey
 * @param dhRecipientCertificate
 * @throws CMSError if `ciphertext` is malformed or could not be decrypted
 *   with `privateKey`
 */
export async function decrypt(
  ciphertext: ArrayBuffer,
  privateKey: CryptoKey,
  dhRecipientCertificate?: Certificate,
): Promise<DecryptionResult> {
  const contentInfo = deserializeContentInfo(ciphertext);
  const envelopedData = new pkijs.EnvelopedData({ schema: contentInfo });

  const plaintext = await pkijsDecrypt(envelopedData, privateKey, dhRecipientCertificate);

  // When doing key agreement, extract the originator's (EC)DH public key after it's altered by
  // EnvelopedData.decrypt() to unconditionally replace the algorithm parameters (e.g., the curve
  // name):
  const isKeyAgreement = !!dhRecipientCertificate;
  const recipientInfo = envelopedData.recipientInfos[0];
  const dhPublicKeyDer = isKeyAgreement
    ? recipientInfo.value.originator.value.toSchema().toBER(false)
    : undefined;
  const dhKeyId = isKeyAgreement ? extractOriginatorKeyId(envelopedData) : undefined;

  return { plaintext, dhPublicKeyDer, dhKeyId };
}

async function pkijsDecrypt(
  envelopedData: pkijs.EnvelopedData,
  privateKey: CryptoKey,
  dhCertificate?: Certificate,
): Promise<ArrayBuffer> {
  const privateKeyBuffer = await pkijsCrypto.exportKey('pkcs8', privateKey);
  const encryptArgs = {
    recipientCertificate: dhCertificate ? dhCertificate.pkijsCertificate : undefined,
    recipientPrivateKey: privateKeyBuffer,
  };
  try {
    // @ts-ignore
    return await envelopedData.decrypt(0, encryptArgs);
  } catch (error) {
    throw new CMSError(error, `Decryption failed`);
  }
}

function extractOriginatorKeyId(envelopedData: pkijs.EnvelopedData): number {
  const unprotectedAttrs = envelopedData.unprotectedAttrs || [];
  if (unprotectedAttrs.length === 0) {
    throw new CMSError('unprotectedAttrs must be present when using channel session');
  }

  const matchingAttrs = unprotectedAttrs.filter(
    a => a.type === oids.RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
  );
  if (matchingAttrs.length === 0) {
    throw new CMSError('unprotectedAttrs does not contain originator key id');
  }

  const originatorKeyIdAttr = matchingAttrs[0];
  // @ts-ignore
  const originatorKeyIds = originatorKeyIdAttr.values;
  if (originatorKeyIds.length !== 1) {
    throw new CMSError(
      `Originator key id attribute must have exactly one value (got ${originatorKeyIds.length})`,
    );
  }

  const keyIdString = originatorKeyIds[0].valueBlock.toString();
  return parseInt(keyIdString, 10);
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

function generateRandom32BitUnsignedNumber(): number {
  const numberArray = new Uint32Array(4);
  // @ts-ignore
  pkijsCrypto.getRandomValues(numberArray);
  const numberBuffer = Buffer.from(numberArray);
  return numberBuffer.readUInt32LE(0);
}

function deserializeContentInfo(derValue: ArrayBuffer): asn1js.Sequence {
  const asn1Value = deserializeDer(derValue);
  const contentInfo = new pkijs.ContentInfo({ schema: asn1Value });
  return contentInfo.content;
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
