import * as asn1js from 'asn1js';
import * as lodash from 'lodash';
import * as pkijs from 'pkijs';
import { getPkijsCrypto } from '../_utils';
import * as oids from '../oids';
import CertificateAttributes from './CertificateAttributes';
import CertificateError from './CertificateError';

const pkijsCrypto = getPkijsCrypto();

/**
 * Relaynet PKI Certificate.
 *
 * This is a high-level class on top of PKI.js Certificate, to make the use
 * of Relaynet certificates easy and safe.
 */
export default class Certificate {
  /**
   * Deserialize certificate from DER-encoded value.
   *
   * @param certDer DER-encoded X.509 certificate
   * @throws {CertificateError}
   */
  public static deserialize(certDer: ArrayBuffer): Certificate {
    const asn1 = asn1js.fromBER(certDer);
    if (asn1.offset === -1) {
      throw new CertificateError('Certificate is not DER-encoded');
    }
    const pkijsCert = new pkijs.Certificate({ schema: asn1.result });
    const certificate = new Certificate(pkijsCert);
    certificate.validate();
    return certificate;
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

    const issuerPublicKey = issuerCertificate
      ? await issuerCertificate.pkijsCertificate.getPublicKey()
      : attributes.subjectPublicKey;
    const pkijsCert = new pkijs.Certificate({
      extensions: [
        await makeAuthorityKeyIdExtension(issuerPublicKey),
        await makeSubjectKeyIdExtension(attributes.subjectPublicKey)
      ],
      serialNumber: new asn1js.Integer({ value: attributes.serialNumber }),
      version: 2
    });

    // tslint:disable-next-line:no-object-mutation
    pkijsCert.notBefore.value = validityStartDate;
    // tslint:disable-next-line:no-object-mutation
    pkijsCert.notAfter.value = attributes.validityEndDate;

    const address = await computePrivateNodeAddress(
      attributes.subjectPublicKey
    );
    pkijsCert.subject.typesAndValues.push(
      new pkijs.AttributeTypeAndValue({
        type: oids.COMMON_NAME,
        value: new asn1js.BmpString({ value: address })
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
  public serialize(): ArrayBuffer {
    const certAsn1js = this.pkijsCertificate.toSchema(true);
    return certAsn1js.toBER(false);
  }

  /**
   * Get the Relaynet node address from the subject Common Name (CN).
   */
  public getAddress(): string {
    const matchingDnAttr = this.pkijsCertificate.subject.typesAndValues.filter(
      a => ((a.type as unknown) as string) === oids.COMMON_NAME
    );
    if (matchingDnAttr.length === 0) {
      throw new CertificateError(
        'Could not find subject node address in certificate'
      );
    }
    return matchingDnAttr[0].value.valueBlock.value;
  }

  public validate(): void {
    // X.509 versioning starts at 0
    const x509CertVersion = this.pkijsCertificate.version + 1;
    if (x509CertVersion !== 3) {
      throw new CertificateError(
        `Only X.509 v3 certificates are supported (got v${x509CertVersion})`
      );
    }
  }
}

async function makeAuthorityKeyIdExtension(
  publicKey: CryptoKey
): Promise<pkijs.Extension> {
  const keyDigest = await getPublicKeyDigest(publicKey);
  const keyIdEncoded = new asn1js.OctetString({ valueHex: keyDigest });
  return new pkijs.Extension({
    extnID: oids.AUTHORITY_KEY_ID,
    extnValue: new pkijs.AuthorityKeyIdentifier({ keyIdentifier: keyIdEncoded })
      .toSchema()
      .toBER(false)
  });
}

async function makeSubjectKeyIdExtension(
  publicKey: CryptoKey
): Promise<pkijs.Extension> {
  const keyDigest = await getPublicKeyDigest(publicKey);
  return new pkijs.Extension({
    extnID: oids.SUBJECT_KEY_ID,
    extnValue: new asn1js.OctetString({ valueHex: keyDigest }).toBER(false)
  });
}

async function computePrivateNodeAddress(
  publicKey: CryptoKey
): Promise<string> {
  const publicKeyDigest = Buffer.from(await getPublicKeyDigest(publicKey));
  return `0${publicKeyDigest.toString('hex')}`;
}

async function getPublicKeyDigest(publicKey: CryptoKey): Promise<ArrayBuffer> {
  const publicKeyDer = await pkijsCrypto.exportKey('spki', publicKey);
  return pkijsCrypto.digest({ name: 'SHA-256' }, publicKeyDer);
}
