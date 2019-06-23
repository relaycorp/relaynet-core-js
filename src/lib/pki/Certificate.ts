import * as asn1js from 'asn1js';
import bufferToArrayBuffer from 'buffer-to-arraybuffer';
import * as pkijs from 'pkijs';
import CertificateAttributes from './CertificateAttributes';
import CertificateError from './CertificateError';

export default class Certificate {
  /**
   * Initialize certificate from DER-encoded value.
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

  public static async issue(
    issuerPrivateKey: CryptoKey,
    attributes: CertificateAttributes
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

    await pkijsCert.subjectPublicKeyInfo.importKey(attributes.subjectPublicKey);

    const signatureHashAlgo = (issuerPrivateKey.algorithm as RsaHashedKeyGenParams)
      .hash as Algorithm;
    await pkijsCert.sign(issuerPrivateKey, signatureHashAlgo.name);
    return new Certificate(pkijsCert);
  }

  protected constructor(public readonly pkijsCertificate: pkijs.Certificate) {}
}
