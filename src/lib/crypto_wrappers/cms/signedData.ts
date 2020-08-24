// tslint:disable:no-object-mutation

import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import * as pkijs from 'pkijs';

import * as oids from '../../oids';
import { getPkijsCrypto } from '../_utils';
import Certificate from '../x509/Certificate';
import { deserializeContentInfo } from './_utils';
import CMSError from './CMSError';
import { SignatureOptions } from './SignatureOptions';

const pkijsCrypto = getPkijsCrypto();

export interface SignatureVerification {
  readonly plaintext: ArrayBuffer;
  readonly signerCertificate: Certificate;
  readonly attachedCertificates: readonly Certificate[];
}

export class SignedData {
  public static async sign(
    plaintext: ArrayBuffer,
    privateKey: CryptoKey,
    signerCertificate: Certificate,
    caCertificates: readonly Certificate[] = [],
    options: Partial<SignatureOptions> = {},
  ): Promise<SignedData> {
    // RS-018 prohibits the use of MD5 and SHA-1, but WebCrypto doesn't support MD5
    if (options.hashingAlgorithmName === 'SHA-1') {
      throw new CMSError('SHA-1 is disallowed by RS-018');
    }

    const hashingAlgorithmName = options.hashingAlgorithmName || 'SHA-256';
    const digest = await pkijsCrypto.digest({ name: hashingAlgorithmName }, plaintext);
    const signerInfo = initSignerInfo(signerCertificate, digest);
    const pkijsSignedData = new pkijs.SignedData({
      certificates: [signerCertificate, ...caCertificates].map((c) => c.pkijsCertificate),
      encapContentInfo: new pkijs.EncapsulatedContentInfo({
        eContent: new asn1js.OctetString({ valueHex: plaintext }),
        eContentType: oids.CMS_DATA,
      }),
      signerInfos: [signerInfo],
      version: 1,
    });
    await pkijsSignedData.sign(privateKey, 0, hashingAlgorithmName);

    return new SignedData(pkijsSignedData);
  }

  constructor(public readonly pkijsSignedData: pkijs.SignedData) {}

  public serialize(): ArrayBuffer {
    const contentInfo = new pkijs.ContentInfo({
      content: this.pkijsSignedData.toSchema(true),
      contentType: oids.CMS_SIGNED_DATA,
    });
    return contentInfo.toSchema().toBER(false);
  }
}

/**
 * Generate DER-encoded CMS SignedData signature for `plaintext`.
 *
 * @param plaintext
 * @param privateKey
 * @param signerCertificate
 * @param caCertificates
 * @param options
 * @throws `CMSError` when attempting to use SHA-1 as the hashing function
 */
export async function sign(
  plaintext: ArrayBuffer,
  privateKey: CryptoKey,
  signerCertificate: Certificate,
  caCertificates: readonly Certificate[] = [],
  options: Partial<SignatureOptions> = {},
): Promise<ArrayBuffer> {
  const signedData = await SignedData.sign(
    plaintext,
    privateKey,
    signerCertificate,
    caCertificates,
    options,
  );
  return signedData.serialize();
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
 * Verify CMS SignedData `signature`.
 *
 * The CMS SignedData value must have the signer's certificate attached. CA certificates may
 * also be attached.
 *
 * @param cmsSignedDataSerialized The CMS SignedData signature, DER-encoded.
 * @return Signer's certificate chain, starting with the signer's certificate
 * @throws {CMSError} If `signature` could not be decoded or verified.
 */
export async function verifySignature(
  cmsSignedDataSerialized: ArrayBuffer,
): Promise<SignatureVerification> {
  const contentInfo = deserializeContentInfo(cmsSignedDataSerialized);

  const signedData = new pkijs.SignedData({ schema: contentInfo.content });

  // PKI.js is too slow at verifying the signature if the content is embedded (around 700ms for a
  // 8 MiB content), but passing the content explicitly halves the time.
  const plaintext = extractSignedDataContent(signedData.encapContentInfo);

  // tslint:disable-next-line:no-let
  let verificationResult;
  try {
    verificationResult = await signedData.verify({
      data: plaintext,
      extendedMode: true,
      signer: 0,
    });

    if (!verificationResult.signatureVerified) {
      throw verificationResult;
    }
  } catch (e) {
    throw new CMSError(`Invalid signature: ${e.message} (PKI.js code: ${e.code})`);
  }

  return {
    attachedCertificates: (signedData.certificates as readonly pkijs.Certificate[]).map(
      (c) => new Certificate(c),
    ),
    plaintext,
    signerCertificate: new Certificate(verificationResult.signerCertificate as pkijs.Certificate),
  };
}

function extractSignedDataContent(encapContentInfo: pkijs.EncapsulatedContentInfo): ArrayBuffer {
  if (encapContentInfo.eContent === undefined) {
    throw new CMSError('CMS SignedData value should encapsulate content');
  }
  // ASN1.js splits the payload into 65 kib chunks, so we need to put them back together
  const contentOctetStringChunks = encapContentInfo.eContent.valueBlock.value;
  const contentChunks = contentOctetStringChunks.map(
    (os) => (os as asn1js.OctetString).valueBlock.valueHex,
  );
  const content = Buffer.concat(contentChunks.map((c) => new Uint8Array(c)));

  // tslint:disable-next-line:no-delete
  delete encapContentInfo.eContent;

  return bufferToArray(content);
}
