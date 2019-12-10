import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

import { deserializeDer, getPkijsCrypto } from '../../_utils';
import * as oids from '../../oids';
import CertificateError from './CertificateError';
import CertificateOptions from './CertificateOptions';

const pkijsCrypto = getPkijsCrypto();

/**
 * X.509 Certificate.
 *
 * This is a high-level class on top of PKI.js Certificate, to make the use of Relaynet
 * certificates easy and safe.
 */
export default class Certificate {
  /**
   * Deserialize certificate from DER-encoded value.
   *
   * @param certDer DER-encoded X.509 certificate
   * @throws {CertificateError}
   */
  public static deserialize(certDer: ArrayBuffer): Certificate {
    const asn1Value = deserializeDer(certDer);
    const pkijsCert = new pkijs.Certificate({ schema: asn1Value });
    const certificate = new Certificate(pkijsCert);
    certificate.validate();
    return certificate;
  }

  /**
   * Issue a Relaynet PKI certificate.
   *
   * @param issuerPrivateKey
   * @param options
   * @param issuerCertificate Absent when the certificate is self-signed
   */
  public static async issue(
    issuerPrivateKey: CryptoKey,
    options: CertificateOptions,
    issuerCertificate?: Certificate,
  ): Promise<Certificate> {
    //region Validation
    const validityStartDate = options.validityStartDate || new Date();
    if (options.validityEndDate < validityStartDate) {
      throw new CertificateError('The end date must be later than the start date');
    }

    if (issuerCertificate) {
      validateIssuerCertificate(issuerCertificate);
    }
    //endregion

    const issuerPublicKey = issuerCertificate
      ? await issuerCertificate.pkijsCertificate.getPublicKey()
      : options.subjectPublicKey;
    const pkijsCert = new pkijs.Certificate({
      extensions: [
        makeBasicConstraintsExtension(options.isCA === true),
        await makeAuthorityKeyIdExtension(issuerPublicKey),
        await makeSubjectKeyIdExtension(options.subjectPublicKey),
      ],
      serialNumber: new asn1js.Integer({ value: options.serialNumber }),
      version: 2, // 2 = v3
    });

    // tslint:disable-next-line:no-object-mutation
    pkijsCert.notBefore.value = validityStartDate;
    // tslint:disable-next-line:no-object-mutation
    pkijsCert.notAfter.value = options.validityEndDate;

    const address = await computePrivateNodeAddress(options.subjectPublicKey);
    pkijsCert.subject.typesAndValues.push(
      new pkijs.AttributeTypeAndValue({
        type: oids.COMMON_NAME,
        value: new asn1js.BmpString({ value: address }),
      }),
    );

    const issuerDn = issuerCertificate
      ? issuerCertificate.pkijsCertificate.subject.typesAndValues
      : pkijsCert.subject.typesAndValues;
    // tslint:disable-next-line:no-object-mutation
    pkijsCert.issuer.typesAndValues = issuerDn.map(
      attribute =>
        new pkijs.AttributeTypeAndValue({
          type: attribute.type,
          value: cloneAsn1jsValue(attribute.value),
        }),
    );

    await pkijsCert.subjectPublicKeyInfo.importKey(options.subjectPublicKey);

    const signatureHashAlgo = (issuerPrivateKey.algorithm as RsaHashedKeyGenParams)
      .hash as Algorithm;
    await pkijsCert.sign(issuerPrivateKey, signatureHashAlgo.name);
    return new Certificate(pkijsCert);
  }

  public constructor(public readonly pkijsCertificate: pkijs.Certificate) {}

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
      a => ((a.type as unknown) as string) === oids.COMMON_NAME,
    );
    if (matchingDnAttr.length === 0) {
      throw new CertificateError('Could not find subject node address in certificate');
    }
    return matchingDnAttr[0].value.valueBlock.value;
  }

  public validate(): void {
    // X.509 versioning starts at 0
    const x509CertVersion = this.pkijsCertificate.version + 1;
    if (x509CertVersion !== 3) {
      throw new CertificateError(
        `Only X.509 v3 certificates are supported (got v${x509CertVersion})`,
      );
    }
  }
}

//region Extensions

function makeBasicConstraintsExtension(isCA: boolean): pkijs.Extension {
  return new pkijs.Extension({
    critical: true,
    extnID: oids.BASIC_CONSTRAINTS,
    extnValue: new pkijs.BasicConstraints({ cA: isCA }).toSchema().toBER(false),
  });
}

async function makeAuthorityKeyIdExtension(publicKey: CryptoKey): Promise<pkijs.Extension> {
  const keyDigest = await getPublicKeyDigest(publicKey);
  const keyIdEncoded = new asn1js.OctetString({ valueHex: keyDigest });
  return new pkijs.Extension({
    extnID: oids.AUTHORITY_KEY,
    extnValue: new pkijs.AuthorityKeyIdentifier({ keyIdentifier: keyIdEncoded })
      .toSchema()
      .toBER(false),
  });
}

async function makeSubjectKeyIdExtension(publicKey: CryptoKey): Promise<pkijs.Extension> {
  const keyDigest = await getPublicKeyDigest(publicKey);
  return new pkijs.Extension({
    extnID: oids.SUBJECT_KEY,
    extnValue: new asn1js.OctetString({ valueHex: keyDigest }).toBER(false),
  });
}

//endregion

//region Validation

function validateIssuerCertificate(issuerCertificate: Certificate): void {
  const extensions = issuerCertificate.pkijsCertificate.extensions || [];
  const matchingExtensions = extensions.filter(e => e.extnID === oids.BASIC_CONSTRAINTS);
  if (matchingExtensions.length === 0) {
    throw new CertificateError('Basic constraints extension is missing from issuer certificate');
  }
  const extension = matchingExtensions[0];
  const basicConstraintsAsn1 = deserializeDer(extension.extnValue.valueBlock.valueHex);
  const basicConstraints = new pkijs.BasicConstraints({ schema: basicConstraintsAsn1 });
  if (!basicConstraints.cA) {
    throw new CertificateError('Issuer is not a CA');
  }
}

//endregion

async function computePrivateNodeAddress(publicKey: CryptoKey): Promise<string> {
  const publicKeyDigest = Buffer.from(await getPublicKeyDigest(publicKey));
  return `0${publicKeyDigest.toString('hex')}`;
}

async function getPublicKeyDigest(publicKey: CryptoKey): Promise<ArrayBuffer> {
  const publicKeyDer = await pkijsCrypto.exportKey('spki', publicKey);
  return pkijsCrypto.digest({ name: 'SHA-256' }, publicKeyDer);
}

interface Asn1jsSerializable {
  readonly toBER: (sizeOnly?: boolean) => ArrayBuffer;
}

function cloneAsn1jsValue(value: Asn1jsSerializable): asn1js.LocalBaseBlock {
  const valueSerialized = value.toBER(false);
  return deserializeDer(valueSerialized);
}
