// tslint:disable:no-object-mutation max-classes-per-file
import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import * as pkijs from 'pkijs';

import * as oids from '../../oids';
import { getPkijsCrypto } from '../_utils';
import { derDeserializeECDHPublicKey, derSerializePrivateKey } from '../keys';
import Certificate from '../x509/Certificate';
import { deserializeContentInfo } from './_utils';
import CMSError from './CMSError';

const pkijsCrypto = getPkijsCrypto();

const AES_KEY_SIZES: ReadonlyArray<number> = [128, 192, 256];

export interface EncryptionOptions {
  readonly aesKeySize: number;
}

export interface SessionEncryptionResult {
  readonly dhKeyId: number;
  readonly dhPrivateKey: CryptoKey; // DH or ECDH key
  readonly envelopedData: SessionEnvelopedData;
}

export interface SessionOriginatorKey {
  readonly keyId: number;
  readonly publicKey: CryptoKey; // DH or ECDH key
}

export abstract class EnvelopedData {
  /**
   * Deserialize an EnvelopedData value into a `SessionlessEnvelopedData` or `SessionEnvelopedData`
   * instance.
   *
   * Depending on the type of RecipientInfo.
   *
   * @param envelopedDataSerialized
   */
  public static deserialize(envelopedDataSerialized: ArrayBuffer): EnvelopedData {
    const contentInfo = deserializeContentInfo(envelopedDataSerialized);
    if (contentInfo.contentType !== oids.CMS_ENVELOPED_DATA) {
      throw new CMSError(
        `ContentInfo does not wrap an EnvelopedData value (got OID ${contentInfo.contentType})`,
      );
    }
    // tslint:disable-next-line:no-let
    let pkijsEnvelopedData;
    try {
      pkijsEnvelopedData = new pkijs.EnvelopedData({ schema: contentInfo.content });
    } catch (error) {
      throw new CMSError(error, 'Invalid EnvelopedData value');
    }
    const recipientInfosLength = pkijsEnvelopedData.recipientInfos.length;
    if (recipientInfosLength !== 1) {
      throw new CMSError(
        `EnvelopedData must have exactly one RecipientInfo (got ${recipientInfosLength})`,
      );
    }

    const recipientInfo = pkijsEnvelopedData.recipientInfos[0];
    if (![1, 2].includes(recipientInfo.variant)) {
      throw new CMSError(`Unsupported RecipientInfo (variant: ${recipientInfo.variant})`);
    }
    const envelopedDataClass =
      recipientInfo.variant === 1 ? SessionlessEnvelopedData : SessionEnvelopedData;
    return new envelopedDataClass(pkijsEnvelopedData);
  }

  protected constructor(readonly pkijsEnvelopedData: pkijs.EnvelopedData) {}

  public serialize(): ArrayBuffer {
    const contentInfo = new pkijs.ContentInfo({
      content: this.pkijsEnvelopedData.toSchema(),
      contentType: oids.CMS_ENVELOPED_DATA,
    });
    return contentInfo.toSchema().toBER(false);
  }

  public abstract async decrypt(privateKey: CryptoKey): Promise<ArrayBuffer>;
}

/**
 * CMS EnvelopedData representation using key transport (KeyTransRecipientInfo).
 */
export class SessionlessEnvelopedData extends EnvelopedData {
  public static async encrypt(
    plaintext: ArrayBuffer,
    certificate: Certificate,
    options: Partial<EncryptionOptions> = {},
  ): Promise<SessionlessEnvelopedData> {
    const pkijsEnvelopedData = new pkijs.EnvelopedData();

    pkijsEnvelopedData.addRecipientByCertificate(
      certificate.pkijsCertificate,
      { oaepHashAlgorithm: 'SHA-256' },
      1,
    );

    const aesKeySize = getAesKeySize(options.aesKeySize);
    await pkijsEnvelopedData.encrypt(
      // @ts-ignore
      { name: 'AES-GCM', length: aesKeySize },
      plaintext,
    );

    return new SessionlessEnvelopedData(pkijsEnvelopedData);
  }

  public async decrypt(privateKey: CryptoKey): Promise<ArrayBuffer> {
    return pkijsDecrypt(this.pkijsEnvelopedData, privateKey);
  }
}

function getAesKeySize(aesKeySize: number | undefined): number {
  if (aesKeySize && !AES_KEY_SIZES.includes(aesKeySize)) {
    throw new CMSError(`Invalid AES key size (${aesKeySize})`);
  }
  return aesKeySize || 128;
}

/**
 * CMS EnvelopedData representation using key agreement (KeyAgreeRecipientInfo).
 *
 * Or more specifically, using Relaynet's channel session protocol.
 */
export class SessionEnvelopedData extends EnvelopedData {
  public static async encrypt(
    plaintext: ArrayBuffer,
    certificateOrOriginatorKey: Certificate | SessionOriginatorKey,
    options: Partial<EncryptionOptions> = {},
  ): Promise<SessionEncryptionResult> {
    // Generate id for generated (EC)DH key and attach it to unprotectedAttrs per RS-003:
    const dhKeyId = generateRandom32BitUnsignedNumber();
    const serialNumberAttribute = new pkijs.Attribute({
      type: oids.RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
      values: [new asn1js.Integer({ value: dhKeyId })],
    });

    const pkijsEnvelopedData = new pkijs.EnvelopedData({
      unprotectedAttrs: [serialNumberAttribute],
    });

    const pkijsCertificate = await getOrMakePkijsCertificate(certificateOrOriginatorKey);
    pkijsEnvelopedData.addRecipientByCertificate(pkijsCertificate, {}, 2);

    const aesKeySize = getAesKeySize(options.aesKeySize);
    const [pkijsEncryptionResult] = await pkijsEnvelopedData.encrypt(
      // @ts-ignore
      { name: 'AES-GCM', length: aesKeySize },
      plaintext,
    );
    const dhPrivateKey = pkijsEncryptionResult.ecdhPrivateKey;

    // pkijs.EnvelopedData.encrypt() deleted the algorithm params so we should reinstate them:
    pkijsEnvelopedData.recipientInfos[0].value.originator.value.algorithm.algorithmParams =
      pkijsCertificate.subjectPublicKeyInfo.algorithm.algorithmParams;

    const envelopedData = new SessionEnvelopedData(pkijsEnvelopedData);
    return { dhPrivateKey, dhKeyId, envelopedData };
  }

  public async getOriginatorKey(): Promise<SessionOriginatorKey> {
    const keyId = extractOriginatorKeyId(this.pkijsEnvelopedData);

    const recipientInfo = this.pkijsEnvelopedData.recipientInfos[0];
    if (recipientInfo.variant !== 2) {
      throw new CMSError(`Expected KeyAgreeRecipientInfo (got variant: ${recipientInfo.variant})`);
    }
    const originator = recipientInfo.value.originator.value;
    const publicKeyDer = originator.toSchema().toBER(false);

    const curveOid = originator.algorithm.algorithmParams.valueBlock.toString();
    // @ts-ignore
    const curveParams = pkijsCrypto.getAlgorithmByOID(curveOid);
    const publicKey = await derDeserializeECDHPublicKey(
      Buffer.from(publicKeyDer),
      curveParams.name,
    );
    return { keyId, publicKey };
  }

  public getRecipientKeyId(): number {
    const keyInfo = this.pkijsEnvelopedData.recipientInfos[0].value;
    const encryptedKey = keyInfo.recipientEncryptedKeys.encryptedKeys[0];
    return convertAsn1IntegerToNumber(encryptedKey.rid.value.serialNumber);
  }

  public async decrypt(dhPrivateKey: CryptoKey): Promise<ArrayBuffer> {
    const originator = this.pkijsEnvelopedData.recipientInfos[0].value.originator;
    const dhCertificate: pkijs.Certificate = {
      subjectPublicKeyInfo: {
        // @ts-ignore
        algorithm: {
          algorithmParams: originator.value.algorithm.algorithmParams,
        },
      },
    };
    return pkijsDecrypt(this.pkijsEnvelopedData, dhPrivateKey, dhCertificate);
  }
}

async function pkijsDecrypt(
  envelopedData: pkijs.EnvelopedData,
  privateKey: CryptoKey,
  dhCertificate?: pkijs.Certificate,
): Promise<ArrayBuffer> {
  const privateKeyDer = await derSerializePrivateKey(privateKey);
  const encryptArgs = {
    recipientCertificate: dhCertificate,
    recipientPrivateKey: bufferToArray(privateKeyDer),
  };
  try {
    // @ts-ignore
    return await envelopedData.decrypt(0, encryptArgs);
  } catch (error) {
    throw new CMSError(error, 'Decryption failed');
  }
}

async function getOrMakePkijsCertificate(
  certificateOrOriginatorKey: Certificate | SessionOriginatorKey,
): Promise<pkijs.Certificate> {
  // PKI.js requires the entire recipient's **certificate** to decrypt, but the only thing it
  // uses it for is to get the public key algorithm. Which you can get from the private key.
  if (certificateOrOriginatorKey instanceof Certificate) {
    return certificateOrOriginatorKey.pkijsCertificate;
  }

  const pkijsCertificate = new pkijs.Certificate({
    serialNumber: new asn1js.Integer({ value: certificateOrOriginatorKey.keyId }),
  });
  await pkijsCertificate.subjectPublicKeyInfo.importKey(certificateOrOriginatorKey.publicKey);
  return pkijsCertificate;
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

  return convertAsn1IntegerToNumber(originatorKeyIds[0]);
}

function convertAsn1IntegerToNumber(asn1Integer: asn1js.Integer): number {
  const keyIdString = asn1Integer.valueBlock.toString();
  return parseInt(keyIdString, 10);
}

function generateRandom32BitUnsignedNumber(): number {
  const numberArray = new Uint32Array(4);
  // @ts-ignore
  pkijsCrypto.getRandomValues(numberArray);
  const numberBuffer = Buffer.from(numberArray);
  return numberBuffer.readUInt32LE(0);
}
