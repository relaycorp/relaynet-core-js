// tslint:disable:no-object-mutation

import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

import { CMS_OIDS } from '../../oids';
import { getPkijsCrypto } from '../_utils';
import { getEngineForPrivateKey } from '../pkijs';
import { Certificate } from '../x509/Certificate';
import { deserializeContentInfo } from './_utils';
import { CMSError } from './CMSError';
import { SignatureOptions } from './SignatureOptions';

const pkijsCrypto = getPkijsCrypto();

export interface SignatureVerification {
  readonly plaintext: ArrayBuffer;
  readonly signerCertificate: Certificate;
  readonly attachedCertificates: readonly Certificate[];
}

interface SignedDataOptions extends SignatureOptions {
  readonly encapsulatePlaintext: boolean;
}

export class SignedData {
  /**
   * The signed plaintext, if it was encapsulated.
   */
  get plaintext(): ArrayBuffer | null {
    const eContent = this.pkijsSignedData.encapContentInfo.eContent;
    return eContent?.getValue() ?? null;
  }

  /**
   * The signer's certificate, if it was encapsulated.
   */
  get signerCertificate(): Certificate | null {
    if (this.pkijsSignedData.signerInfos.length === 0) {
      return null;
    }
    const signerInfo = this.pkijsSignedData.signerInfos[0];
    const matches = Array.from(this.certificates).filter(
      (c) =>
        c.pkijsCertificate.issuer.isEqual(signerInfo.sid.issuer) &&
        c.pkijsCertificate.serialNumber.isEqual(signerInfo.sid.serialNumber),
    );
    return matches[0] ?? null;
  }

  /**
   * Set of encapsulated certificates.
   */
  get certificates(): Set<Certificate> {
    const certificates = (this.pkijsSignedData.certificates as readonly pkijs.Certificate[]).map(
      (c) => new Certificate(c),
    );
    return new Set(certificates);
  }

  public static async sign(
    plaintext: ArrayBuffer,
    privateKey: CryptoKey,
    signerCertificate: Certificate,
    caCertificates: readonly Certificate[] = [],
    options: Partial<SignedDataOptions> = {},
  ): Promise<SignedData> {
    // RS-018 prohibits the use of MD5 and SHA-1, but WebCrypto doesn't support MD5
    if ((options.hashingAlgorithmName as any) === 'SHA-1') {
      throw new CMSError('SHA-1 is disallowed by RS-018');
    }

    const hashingAlgorithmName = options.hashingAlgorithmName || 'SHA-256';
    const digest = await pkijsCrypto.digest({ name: hashingAlgorithmName }, plaintext);
    const signerInfo = initSignerInfo(signerCertificate, digest);
    const encapsulatePlaintext = options.encapsulatePlaintext ?? true;
    const pkijsSignedData = new pkijs.SignedData({
      certificates: [signerCertificate, ...caCertificates].map((c) => c.pkijsCertificate),
      encapContentInfo: new pkijs.EncapsulatedContentInfo({
        eContentType: CMS_OIDS.DATA,
        ...(encapsulatePlaintext && { eContent: new asn1js.OctetString({ valueHex: plaintext }) }),
      }),
      signerInfos: [signerInfo],
      version: 1,
    });
    await pkijsSignedData.sign(
      privateKey,
      0,
      hashingAlgorithmName,
      encapsulatePlaintext ? undefined : plaintext,
      getEngineForPrivateKey(privateKey),
    );

    return SignedData.reDeserialize(pkijsSignedData);
  }

  public static deserialize(signedDataSerialized: ArrayBuffer): SignedData {
    const contentInfo = deserializeContentInfo(signedDataSerialized);
    let pkijsSignedData: pkijs.SignedData;
    try {
      pkijsSignedData = new pkijs.SignedData({ schema: contentInfo.content });
    } catch (exc) {
      throw new CMSError('SignedData value is malformed', exc);
    }
    return new SignedData(pkijsSignedData);
  }

  /**
   *
   * @param pkijsSignedData
   * @private
   */
  private static reDeserialize(pkijsSignedData: pkijs.SignedData): SignedData {
    const signedData = new SignedData(pkijsSignedData);
    const serialization = signedData.serialize();
    return SignedData.deserialize(serialization);
  }

  constructor(public readonly pkijsSignedData: pkijs.SignedData) {}

  public serialize(): ArrayBuffer {
    const contentInfo = new pkijs.ContentInfo({
      content: this.pkijsSignedData.toSchema(true),
      contentType: CMS_OIDS.SIGNED_DATA,
    });
    return contentInfo.toSchema().toBER(false);
  }

  public async verify(expectedPlaintext?: ArrayBuffer): Promise<void> {
    const currentPlaintext = this.plaintext;
    const isPlaintextEncapsulated = currentPlaintext !== null;
    if (isPlaintextEncapsulated && expectedPlaintext !== undefined) {
      throw new CMSError(
        'No specific plaintext should be expected because one is already encapsulated',
      );
    }
    if (!isPlaintextEncapsulated && expectedPlaintext === undefined) {
      throw new CMSError('Plaintext should be encapsulated or explicitly set');
    }

    let verificationResult;
    try {
      verificationResult = await this.pkijsSignedData.verify({
        data: isPlaintextEncapsulated ? undefined : expectedPlaintext,
        extendedMode: true,
        signer: 0,
      });
    } catch (err: any) {
      throw new CMSError(`Invalid signature: ${err.message} (PKI.js code: ${err.code})`);
    }

    if (!verificationResult.signatureVerified) {
      throw new CMSError(`Invalid signature (PKI.js code: ${verificationResult.code})`);
    }
  }
}

/**
 * Generate DER-encoded CMS SignedData signature for `plaintext`.
 *
 * TODO: REMOVE
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
    type: CMS_OIDS.ATTR_CONTENT_TYPE,
    values: [new asn1js.ObjectIdentifier({ value: CMS_OIDS.DATA })],
  });
  const digestAttribute = new pkijs.Attribute({
    type: CMS_OIDS.ATTR_DIGEST,
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
 *
 * TODO: Remove
 */
export async function verifySignature(
  cmsSignedDataSerialized: ArrayBuffer,
): Promise<SignatureVerification> {
  const signedData = SignedData.deserialize(cmsSignedDataSerialized);
  await signedData.verify();

  return {
    attachedCertificates: Array.from(signedData.certificates),
    plaintext: signedData.plaintext!,
    signerCertificate: signedData.signerCertificate as Certificate,
  };
}
