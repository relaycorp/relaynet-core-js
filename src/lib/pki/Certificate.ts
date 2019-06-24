import * as asn1js from 'asn1js';
import bufferToArrayBuffer from 'buffer-to-arraybuffer';
import { createHash } from 'crypto';
import * as lodash from 'lodash';
import * as pkijs from 'pkijs';
import { getPkijsCrypto } from './_utils';
import CertificateAttributes from './CertificateAttributes';
import CertificateError from './CertificateError';

const OID_COMMON_NAME = '2.5.4.3';

export default class Certificate {
  /**
   * Deserialize certificate from DER-encoded value.
   *
   * @param certDer DER-encoded X.509 certificate
   * @throws {CertificateError}
   */
  public static deserialize(certDer: Buffer): Certificate {
    const asn1 = asn1js.fromBER(bufferToArrayBuffer(certDer));
    if (asn1.offset === -1) {
      throw new CertificateError('Certificate is not DER-encoded');
    }
    const pkijsCert = new pkijs.Certificate({ schema: asn1.result });
    return new Certificate(pkijsCert);
  }

  /**
   * Issue a Relaynet PKI certificate.
   *
   * @param issuerPrivateKey
   * @param attributes
   * @param issuerCertificate Absent when the certificate is self-signed
   */
  public static async issue(
    issuerPrivateKey: CryptoKey,
    attributes: CertificateAttributes,
    issuerCertificate?: Certificate
  ): Promise<Certificate> {
    const validityStartDate = attributes.validityStartDate || new Date();
    if (attributes.validityEndDate < validityStartDate) {
      throw new CertificateError(
        'The end date must be later than the start date'
      );
    }

    const pkijsCert = new pkijs.Certificate({
      serialNumber: new asn1js.Integer({ value: attributes.serialNumber }),
      version: 2
    });

    // tslint:disable-next-line:no-object-mutation
    pkijsCert.notBefore.value = validityStartDate;
    // tslint:disable-next-line:no-object-mutation
    pkijsCert.notAfter.value = attributes.validityEndDate;

    const nodeAddress =
      attributes.publicAddress ||
      (await computePrivateNodeAddress(attributes.subjectPublicKey));
    pkijsCert.subject.typesAndValues.push(
      new pkijs.AttributeTypeAndValue({
        type: OID_COMMON_NAME,
        value: new asn1js.BmpString({ value: nodeAddress })
      })
    );

    const issuerDn = issuerCertificate
      ? issuerCertificate.pkijsCertificate.subject.typesAndValues
      : pkijsCert.subject.typesAndValues;
    // tslint:disable-next-line:no-object-mutation
    pkijsCert.issuer.typesAndValues = issuerDn.map(
      attribute =>
        new pkijs.AttributeTypeAndValue({
          type: attribute.type,
          value: lodash.cloneDeep(attribute.value)
        })
    );

    await pkijsCert.subjectPublicKeyInfo.importKey(attributes.subjectPublicKey);

    const signatureHashAlgo = (issuerPrivateKey.algorithm as RsaHashedKeyGenParams)
      .hash as Algorithm;
    await pkijsCert.sign(issuerPrivateKey, signatureHashAlgo.name);
    return new Certificate(pkijsCert);
  }

  protected constructor(public readonly pkijsCertificate: pkijs.Certificate) {}

  /**
   * Serialize certificate as DER-encoded buffer.
   */
  public serialize(): Buffer {
    const certAsn1js = this.pkijsCertificate.toSchema(true);
    return Buffer.from(certAsn1js.toBER(false));
  }

  public getAddress(): string {
    const matchingDnAttr = this.pkijsCertificate.subject.typesAndValues.filter(
      a => ((a.type as unknown) as string) === OID_COMMON_NAME
    );
    if (matchingDnAttr.length === 0) {
      throw new CertificateError(
        'Could not find subject node address in certificate'
      );
    }
    return matchingDnAttr[0].value.valueBlock.value;
  }
}

async function computePrivateNodeAddress(
  publicKey: CryptoKey
): Promise<string> {
  const pkijsCrypto = getPkijsCrypto();
  const publicKeyDer = Buffer.from(
    await pkijsCrypto.exportKey('spki', publicKey)
  );

  const publicKeyHash = createHash('sha256')
    .update(publicKeyDer)
    .digest('hex');
  return `0${publicKeyHash}`;
}
