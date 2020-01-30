import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

import * as oids from '../../oids';
import { deserializeDer, generateRandom32BitUnsignedNumber } from '../_utils';
import { getPublicKeyDigest } from '../keys';
import CertificateError from './CertificateError';
import CertificateOptions from './CertificateOptions';

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
   * @param options
   */
  public static async issue(options: CertificateOptions): Promise<Certificate> {
    //region Validation
    const validityStartDate = options.validityStartDate || new Date();
    if (options.validityEndDate < validityStartDate) {
      throw new CertificateError('The end date must be later than the start date');
    }

    if (options.issuerCertificate) {
      validateIssuerCertificate(options.issuerCertificate);
    }
    //endregion

    const issuerPublicKey = options.issuerCertificate
      ? await options.issuerCertificate.pkijsCertificate.getPublicKey()
      : options.subjectPublicKey;
    const serialNumber = options.serialNumber ?? generateRandom32BitUnsignedNumber();
    const serialNumberBlock = new asn1js.Integer({ value: serialNumber });
    const pkijsCert = new pkijs.Certificate({
      extensions: [
        makeBasicConstraintsExtension(options.isCA === true),
        await makeAuthorityKeyIdExtension(issuerPublicKey),
        await makeSubjectKeyIdExtension(options.subjectPublicKey),
      ],
      serialNumber: serialNumberBlock,
      version: 2, // 2 = v3
    });

    // tslint:disable-next-line:no-object-mutation
    pkijsCert.notBefore.value = validityStartDate;
    // tslint:disable-next-line:no-object-mutation
    pkijsCert.notAfter.value = options.validityEndDate;

    pkijsCert.subject.typesAndValues.push(
      new pkijs.AttributeTypeAndValue({
        type: oids.COMMON_NAME,
        value: new asn1js.BmpString({ value: options.commonName }),
      }),
    );

    const issuerDn = options.issuerCertificate
      ? options.issuerCertificate.pkijsCertificate.subject.typesAndValues
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

    const signatureHashAlgo = (options.issuerPrivateKey.algorithm as RsaHashedKeyGenParams)
      .hash as Algorithm;
    await pkijsCert.sign(options.issuerPrivateKey, signatureHashAlgo.name);
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
   * Return serial number as a little endian buffer.
   *
   * This doesn't return a `number` or `BigInt` because the serial number could require more than
   * 8 octets (which is the maximum number of octets required to represent a 64-bit unsigned
   * integer).
   *
   * Also, ASN.1 BER/DER integers are serialized in big endian but for consistency with the
   * Relaynet specs and this library, the result uses little endian.
   */
  public getSerialNumber(): Buffer {
    const serialNumberBlock = this.pkijsCertificate.serialNumber;
    const numberBigEndian = new Uint8Array(serialNumberBlock.valueBlock.toBER());
    const numberLittleEndian = numberBigEndian.reverse();
    return Buffer.from(numberLittleEndian);
  }

  public getSerialNumberHex(): string {
    const serialNumber = this.getSerialNumber();
    return serialNumber.toString('hex');
  }

  public getCommonName(): string {
    const matchingDnAttr = this.pkijsCertificate.subject.typesAndValues.filter(
      a => ((a.type as unknown) as string) === oids.COMMON_NAME,
    );
    if (matchingDnAttr.length === 0) {
      throw new CertificateError('Distinguished Name does not contain Common Name');
    }
    return matchingDnAttr[0].value.valueBlock.value;
  }

  public async getPublicKey(): Promise<CryptoKey> {
    return this.pkijsCertificate.getPublicKey();
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

  /**
   * Return the certification path (aka "certificate chain") if this certificate can be trusted.
   *
   * @param intermediateCaCertificates The alleged chain for the certificate
   * @param trustedCertificates The collection of certificates that are actually trusted
   * @throws CertificateError when this certificate is not on a certificate path from a CA in
   *   `trustedCertificates`
   */
  public async getCertificationPath(
    intermediateCaCertificates: readonly Certificate[],
    trustedCertificates: readonly Certificate[],
  ): Promise<readonly Certificate[]> {
    const chainValidator = new pkijs.CertificateChainValidationEngine({
      certs: [...intermediateCaCertificates.map(c => c.pkijsCertificate), this.pkijsCertificate],
      trustedCerts: trustedCertificates.map(c => c.pkijsCertificate),
    });
    const verification = await chainValidator.verify({ passedWhenNotRevValues: false });

    if (!verification.result) {
      throw new CertificateError(verification.resultMessage);
    }

    return verification.certificatePath.map(
      (pkijsCert: pkijs.Certificate) => new Certificate(pkijsCert),
    );
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

interface Asn1jsSerializable {
  readonly toBER: (sizeOnly?: boolean) => ArrayBuffer;
}

function cloneAsn1jsValue(value: Asn1jsSerializable): asn1js.LocalBaseBlock {
  const valueSerialized = value.toBER(false);
  return deserializeDer(valueSerialized);
}
