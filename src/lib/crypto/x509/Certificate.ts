import { BmpString, Integer, OctetString, BaseBlock } from 'asn1js';
import { min, setMilliseconds } from 'date-fns';
import * as pkijs from 'pkijs';

import * as oids from '../../oids';
import { derDeserialize, generateRandom64BitValue } from '../_utils';
import { getEngineForKey, NODE_ENGINE } from '../pkijs';
import { CertificateError } from './CertificateError';
import FullCertificateIssuanceOptions from './FullCertificateIssuanceOptions';
import { assertPkiType, assertUndefined } from '../cms/_utils';
import { getIdFromIdentityKey, getPublicKeyDigest } from '../keys/digest';

const MAX_PATH_LENGTH_CONSTRAINT = 2; // Per Relaynet PKI

/**
 * X.509 Certificate.
 *
 * This is a high-level class on top of PKI.js Certificate, to make the use of Relaynet
 * certificates easy and safe.
 */
export class Certificate {
  get startDate(): Date {
    return this.pkijsCertificate.notBefore.value;
  }

  get expiryDate(): Date {
    return this.pkijsCertificate.notAfter.value;
  }

  /**
   * Deserialize certificate from DER-encoded value.
   *
   * @param certDer DER-encoded X.509 certificate
   */
  public static deserialize(certDer: ArrayBuffer): Certificate {
    const asn1Value = derDeserialize(certDer);
    const pkijsCert = new pkijs.Certificate({ schema: asn1Value });
    return new Certificate(pkijsCert);
  }

  /**
   * Issue a Relaynet PKI certificate.
   *
   * @param options
   */
  public static async issue(options: FullCertificateIssuanceOptions): Promise<Certificate> {
    // PKI.js should round down to the nearest second per X.509. We should do it ourselves to
    // avoid discrepancies when the validity dates of a freshly-issued certificate are used.
    const validityStartDate = setMilliseconds(options.validityStartDate ?? new Date(), 0);
    const issuerCertificate = options.issuerCertificate;
    const validityEndDate = setMilliseconds(
      issuerCertificate
        ? min([issuerCertificate.expiryDate, options.validityEndDate])
        : options.validityEndDate,
      0,
    );

    //region Validation
    if (validityEndDate < validityStartDate) {
      throw new CertificateError('The end date must be later than the start date');
    }
    if (issuerCertificate) {
      validateIssuerCertificate(issuerCertificate);
    }
    //endregion

    const issuerPublicKey = issuerCertificate
      ? await issuerCertificate.pkijsCertificate.getPublicKey(undefined, NODE_ENGINE)
      : options.subjectPublicKey;
    const pkijsCert = new pkijs.Certificate({
      extensions: [
        makeBasicConstraintsExtension(options.isCA === true, options.pathLenConstraint ?? 0),
        await makeAuthorityKeyIdExtension(issuerPublicKey),
        await makeSubjectKeyIdExtension(options.subjectPublicKey),
      ],
      serialNumber: generatePositiveASN1Integer(),
      version: 2, // 2 = v3
    });

    // tslint:disable-next-line:no-object-mutation
    pkijsCert.notBefore.value = validityStartDate;
    // tslint:disable-next-line:no-object-mutation
    pkijsCert.notAfter.value = validityEndDate;

    pkijsCert.subject.typesAndValues.push(
      new pkijs.AttributeTypeAndValue({
        type: oids.COMMON_NAME,
        value: new BmpString({ value: options.commonName }),
      }),
    );

    const issuerDn = issuerCertificate
      ? issuerCertificate.pkijsCertificate.subject.typesAndValues
      : pkijsCert.subject.typesAndValues;
    // tslint:disable-next-line:no-object-mutation
    pkijsCert.issuer.typesAndValues = issuerDn.map(
      (attribute) =>
        new pkijs.AttributeTypeAndValue({
          type: attribute.type,
          value: cloneAsn1jsValue(attribute.value),
        }),
    );

    await pkijsCert.subjectPublicKeyInfo.importKey(
      options.subjectPublicKey,
      getEngineForKey(options.subjectPublicKey),
    );

    const signatureHashAlgo = (options.issuerPrivateKey.algorithm as RsaHashedKeyGenParams)
      .hash as Algorithm;
    const engine = getEngineForKey(options.issuerPrivateKey);
    await pkijsCert.sign(options.issuerPrivateKey, signatureHashAlgo.name, engine);
    return new Certificate(pkijsCert);
  }

  /**
   * @internal
   */
  public readonly pkijsCertificate: pkijs.Certificate;

  // tslint:disable-next-line:readonly-keyword
  protected subjectIdCache: string | null = null;

  /**
   * @internal
   */
  public constructor(pkijsCertificate: pkijs.Certificate) {
    this.pkijsCertificate = pkijsCertificate;
  }

  /**
   * Serialize certificate as DER-encoded buffer.
   */
  public serialize(): ArrayBuffer {
    const certAsn1js = this.pkijsCertificate.toSchema(true);
    return certAsn1js.toBER(false);
  }

  /**
   * Return serial number.
   *
   * This doesn't return a `number` or `BigInt` because the serial number could require more than
   * 8 octets (which is the maximum number of octets required to represent a 64-bit unsigned
   * integer).
   */
  public getSerialNumber(): Buffer {
    const serialNumberBlock = this.pkijsCertificate.serialNumber;
    const serialNumber = serialNumberBlock.valueBlock.toBER();
    return Buffer.from(serialNumber);
  }

  public getSerialNumberHex(): string {
    const serialNumber = this.getSerialNumber();
    return serialNumber.toString('hex');
  }

  public getCommonName(): string {
    const matchingDnAttr = this.pkijsCertificate.subject.typesAndValues.filter(
      (a) => (a.type as unknown as string) === oids.COMMON_NAME,
    );
    if (matchingDnAttr.length === 0) {
      throw new CertificateError('Distinguished Name does not contain Common Name');
    }
    return matchingDnAttr[0].value.valueBlock.value;
  }

  public async getPublicKey(): Promise<CryptoKey> {
    return this.pkijsCertificate.getPublicKey(undefined, NODE_ENGINE);
  }

  /**
   * Report whether this certificate is the same as `otherCertificate`.
   *
   * @param otherCertificate
   */
  public isEqual(otherCertificate: Certificate): boolean {
    const thisCertSerialized = Buffer.from(this.serialize());
    const otherCertSerialized = Buffer.from(otherCertificate.serialize());
    return thisCertSerialized.equals(otherCertSerialized);
  }

  public validate(): void {
    // X.509 versioning starts at 0
    const x509CertVersion = this.pkijsCertificate.version + 1;
    if (x509CertVersion !== 3) {
      throw new CertificateError(
        `Only X.509 v3 certificates are supported (got v${x509CertVersion})`,
      );
    }

    const currentDate = new Date();
    if (currentDate < this.startDate) {
      throw new CertificateError('Certificate is not yet valid');
    }
    if (this.expiryDate < currentDate) {
      throw new CertificateError('Certificate already expired');
    }
  }

  public async calculateSubjectId(): Promise<string> {
    if (!this.subjectIdCache) {
      // tslint:disable-next-line:no-object-mutation
      this.subjectIdCache = await getIdFromIdentityKey(await this.getPublicKey());
    }
    return this.subjectIdCache;
  }

  public getIssuerId(): string | null {
    const authorityKeyAttribute = this.pkijsCertificate.extensions?.find(
      (attr) => attr.extnID === oids.AUTHORITY_KEY,
    );
    if (!authorityKeyAttribute) {
      return null;
    }
    const authorityKeyId = authorityKeyAttribute.parsedValue;
    assertPkiType(authorityKeyId, pkijs.AuthorityKeyIdentifier, 'authorityKeyId');
    assertUndefined(authorityKeyId.keyIdentifier, 'authorityKeyId.keyIdentifier');
    const id = Buffer.from(authorityKeyId.keyIdentifier.valueBlock.valueHexView).toString('hex');
    return `0${id}`;
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
    // Ignore any intermediate certificate that's also the issuer of a trusted certificate.
    // The main reason for doing this isn't performance, but the fact that PKI.js would fail to
    // compute the path.
    const intermediateCertsSanitized = intermediateCaCertificates.filter((c) => {
      for (const trustedCertificate of trustedCertificates) {
        if (trustedCertificate.pkijsCertificate.issuer.isEqual(c.pkijsCertificate.subject)) {
          return false;
        }
      }
      return true;
    });

    const chainValidator = new pkijs.CertificateChainValidationEngine({
      certs: [...intermediateCertsSanitized.map((c) => c.pkijsCertificate), this.pkijsCertificate],
      trustedCerts: trustedCertificates.map((c) => c.pkijsCertificate),
    });
    const verification = await chainValidator.verify(
      { passedWhenNotRevValues: false },
      NODE_ENGINE,
    );

    if (!verification.result) {
      throw new CertificateError(verification.resultMessage);
    }

    return verification.certificatePath!.map(
      (pkijsCert: pkijs.Certificate) => new Certificate(pkijsCert),
    );
  }
}

function generatePositiveASN1Integer(): Integer {
  const potentiallySignedInteger = new Uint8Array(generateRandom64BitValue());

  // ASN.1 BER/DER INTEGER uses two's complement with big endian, so we ensure the integer is
  // positive by keeping the leftmost octet below 128.
  const positiveInteger = new Uint8Array(potentiallySignedInteger);
  positiveInteger.set([Math.min(potentiallySignedInteger[0], 127)], 0);

  return new Integer({ valueHex: positiveInteger });
}

//region Extensions

function makeBasicConstraintsExtension(cA: boolean, pathLenConstraint: number): pkijs.Extension {
  if (pathLenConstraint < 0 || MAX_PATH_LENGTH_CONSTRAINT < pathLenConstraint) {
    throw new CertificateError(
      `pathLenConstraint must be between 0 and 2 (got ${pathLenConstraint})`,
    );
  }
  const basicConstraints = new pkijs.BasicConstraints({ cA, pathLenConstraint });
  return new pkijs.Extension({
    critical: true,
    extnID: oids.BASIC_CONSTRAINTS,
    extnValue: basicConstraints.toSchema().toBER(false),
  });
}

async function makeAuthorityKeyIdExtension(publicKey: CryptoKey): Promise<pkijs.Extension> {
  const keyDigest = await getPublicKeyDigest(publicKey);
  const keyIdEncoded = new OctetString({ valueHex: keyDigest });
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
    extnValue: new OctetString({ valueHex: keyDigest }).toBER(false),
  });
}

//endregion

//region Validation

function validateIssuerCertificate(issuerCertificate: Certificate): void {
  const extensions = issuerCertificate.pkijsCertificate.extensions || [];
  const matchingExtensions = extensions.filter((e) => e.extnID === oids.BASIC_CONSTRAINTS);
  if (matchingExtensions.length === 0) {
    throw new CertificateError('Basic constraints extension is missing from issuer certificate');
  }
  const extension = matchingExtensions[0];
  const basicConstraintsAsn1 = derDeserialize(extension.extnValue.valueBlock.valueHex);
  const basicConstraints = new pkijs.BasicConstraints({ schema: basicConstraintsAsn1 });
  if (!basicConstraints.cA) {
    throw new CertificateError('Issuer is not a CA');
  }
}

//endregion

function cloneAsn1jsValue<T extends BaseBlock>(value: T): T {
  const valueSerialized = value.toBER(false);
  return derDeserialize(valueSerialized) as T;
}
