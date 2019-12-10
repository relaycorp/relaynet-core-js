import * as asn1js from 'asn1js';
import bufferToArrayBuffer from 'buffer-to-arraybuffer';
import * as jestDateMock from 'jest-date-mock';
import * as pkijs from 'pkijs';

import { expectPromiseToReject, generateStubCert, sha256Hex } from '../../_test_utils';
import { deserializeDer, getPkijsCrypto } from '../../_utils';
import * as oids from '../../oids';
import { generateRSAKeyPair } from '../keyGenerators';
import Certificate from './Certificate';
import CertificateError from './CertificateError';

const futureDate = new Date();
futureDate.setDate(futureDate.getDate() + 1);

const pkijsCrypto = getPkijsCrypto();

afterEach(() => {
  jest.restoreAllMocks();
  jestDateMock.clear();
});

describe('deserialize()', () => {
  test('should deserialize valid DER-encoded certificates', async () => {
    // Serialize manually just in this test to avoid depending on .serialize()
    const pkijsCert = (await generateStubCert()).pkijsCertificate;
    const certDer = pkijsCert.toSchema(true).toBER(false);

    const cert = Certificate.deserialize(certDer);

    expect(cert.pkijsCertificate.subject.typesAndValues[0].type).toBe(
      pkijsCert.subject.typesAndValues[0].type,
    );
    expect(cert.pkijsCertificate.subject.typesAndValues[0].value.valueBlock.value).toBe(
      pkijsCert.subject.typesAndValues[0].value.valueBlock.value,
    );
  });

  test('should error out with invalid DER values', () => {
    const invalidDer = bufferToArrayBuffer(Buffer.from('nope'));
    expect(() => Certificate.deserialize(invalidDer)).toThrowWithMessage(
      Error,
      'Value is not DER-encoded',
    );
  });

  test('should validate the certificate', async () => {
    const cert = await generateStubCert();

    const error = new Error('Fewer');
    jest.spyOn(Certificate.prototype, 'validate').mockImplementationOnce(() => {
      throw error;
    });

    expect(() => Certificate.deserialize(cert.serialize())).toThrow(error);
  });
});

describe('issue()', () => {
  const baseCertificateOptions = {
    commonName: 'the CN',
    serialNumber: 1,
    validityEndDate: futureDate,
  };

  // tslint:disable-next-line:no-let
  let keyPair: CryptoKeyPair;
  beforeAll(async () => {
    keyPair = await generateRSAKeyPair();
  });

  test('should create an X.509 v3 certificate', async () => {
    const cert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
    });

    // v3 is serialized as integer 2
    expect(cert.pkijsCertificate.version).toBe(2);
  });

  test('should import the public key into the certificate', async () => {
    spyOn(pkijs.PublicKeyInfo.prototype, 'importKey');
    await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
    });

    expect(pkijs.PublicKeyInfo.prototype.importKey).toBeCalledTimes(1);
    expect(pkijs.PublicKeyInfo.prototype.importKey).toBeCalledWith(keyPair.publicKey);
  });

  test('should be signed with the specified private key', async () => {
    spyOn(pkijs.Certificate.prototype, 'sign');
    await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
    });

    expect(pkijs.Certificate.prototype.sign).toBeCalledTimes(1);
    expect(pkijs.Certificate.prototype.sign).toBeCalledWith(
      keyPair.privateKey,
      ((keyPair.privateKey.algorithm as RsaHashedKeyGenParams).hash as Algorithm).name,
    );
  });

  test('should store the specified serial number', async () => {
    const serialNumber = 2019;
    const cert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: keyPair.privateKey,
      serialNumber,
      subjectPublicKey: keyPair.publicKey,
    });

    expect(cert.pkijsCertificate.serialNumber.valueBlock.valueDec).toBe(serialNumber);
  });

  test('should create a certificate valid from now by default', async () => {
    const now = new Date();
    jestDateMock.advanceTo(now);
    const cert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
    });

    expect(cert.pkijsCertificate.notBefore.value).toEqual(now);
  });

  test('should honor a custom start validity date', async () => {
    const startDate = new Date(2019, 1, 1);
    const cert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
      validityStartDate: startDate,
    });

    expect(cert.pkijsCertificate.notBefore.value).toBe(startDate);
  });

  test('should honor a custom end validity date', async () => {
    const endDate = new Date(futureDate);
    endDate.setDate(futureDate.getDate() + 1);
    const cert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
      validityEndDate: endDate,
    });

    expect(cert.pkijsCertificate.notAfter.value).toBe(endDate);
  });

  test('should not accept an end date before the start date', async () => {
    const startDate = new Date(2019, 1, 1);
    const invalidEndDate = new Date(startDate);
    invalidEndDate.setDate(startDate.getDate() - 1);

    await expect(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
        validityEndDate: invalidEndDate,
        validityStartDate: startDate,
      }),
    ).rejects.toThrow('The end date must be later than the start date');
  });

  test('should store the specified Common Name (CN) in the subject', async () => {
    const { privateKey, publicKey } = await generateRSAKeyPair();
    const commonName = 'this is the CN';
    const cert = await Certificate.issue({
      commonName,
      issuerPrivateKey: privateKey,
      serialNumber: 1,
      subjectPublicKey: publicKey,
      validityEndDate: futureDate,
    });

    const subjectDnAttributes = cert.pkijsCertificate.subject.typesAndValues;
    expect(subjectDnAttributes.length).toBe(1);
    expect(subjectDnAttributes[0].type).toBe(oids.COMMON_NAME);
    expect(subjectDnAttributes[0].value.valueBlock.value).toEqual(commonName);
  });

  test('should set issuer DN to that of subject when self-issuing certificates', async () => {
    const subjectKeyPair = await generateRSAKeyPair();
    const cert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: subjectKeyPair.privateKey,
      subjectPublicKey: subjectKeyPair.publicKey,
    });

    const subjectDn = cert.pkijsCertificate.subject.typesAndValues;
    const issuerDn = cert.pkijsCertificate.issuer.typesAndValues;
    expect(issuerDn.length).toBe(1);
    expect(issuerDn[0].type).toBe(oids.COMMON_NAME);
    expect(issuerDn[0].value.valueBlock.value).toBe(subjectDn[0].value.valueBlock.value);
  });

  test('should accept an issuer marked as CA', async () => {
    const issuerKeyPair = await generateRSAKeyPair();
    const issuerCert = await Certificate.issue({
      ...baseCertificateOptions,
      isCA: true,
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
    });

    await expect(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: issuerCert,
        issuerPrivateKey: issuerKeyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      }),
    ).toResolve();
  });

  test('should refuse an issuer certificate without extensions', async () => {
    const issuerKeyPair = await generateRSAKeyPair();
    const issuerCert = await Certificate.issue({
      ...baseCertificateOptions,
      isCA: false,
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
    });
    // tslint:disable-next-line:no-object-mutation
    issuerCert.pkijsCertificate.extensions = undefined;

    await expectPromiseToReject(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: issuerCert,
        issuerPrivateKey: issuerKeyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      }),
      new CertificateError('Basic constraints extension is missing from issuer certificate'),
    );
  });

  test('should refuse an issuer certificate with an empty set of extensions', async () => {
    const issuerKeyPair = await generateRSAKeyPair();
    const issuerCert = await Certificate.issue({
      ...baseCertificateOptions,
      isCA: false,
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
    });
    // tslint:disable-next-line:no-object-mutation
    issuerCert.pkijsCertificate.extensions = [];

    await expectPromiseToReject(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: issuerCert,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      }),
      new CertificateError('Basic constraints extension is missing from issuer certificate'),
    );
  });

  test('should refuse an issuer certificate without basic constraints extension', async () => {
    const issuerKeyPair = await generateRSAKeyPair();
    const issuerCert = await Certificate.issue({
      ...baseCertificateOptions,
      isCA: false,
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
    });
    // tslint:disable-next-line:no-object-mutation
    issuerCert.pkijsCertificate.extensions = (issuerCert.pkijsCertificate
      .extensions as ReadonlyArray<pkijs.Extension>).filter(
      e => e.extnID !== oids.BASIC_CONSTRAINTS,
    );

    await expectPromiseToReject(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: issuerCert,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      }),
      new CertificateError('Basic constraints extension is missing from issuer certificate'),
    );
  });

  test('should refuse an issuer not marked as CA', async () => {
    const issuerKeyPair = await generateRSAKeyPair();
    const issuerCert = await Certificate.issue({
      ...baseCertificateOptions,
      isCA: false,
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
    });

    await expectPromiseToReject(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: issuerCert,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      }),
      new CertificateError('Issuer is not a CA'),
    );
  });

  test('should set issuer DN to that of CA', async () => {
    const issuerKeyPair = await generateRSAKeyPair();
    const issuerCert = await Certificate.issue({
      ...baseCertificateOptions,
      isCA: true,
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
    });

    const subjectKeyPair = await generateRSAKeyPair();
    const subjectCert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerCertificate: issuerCert,
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: subjectKeyPair.publicKey,
    });

    const subjectCertIssuerDn = subjectCert.pkijsCertificate.issuer.typesAndValues;
    expect(subjectCertIssuerDn.length).toBe(1);
    expect(subjectCertIssuerDn[0].type).toBe(oids.COMMON_NAME);
    const issuerCn = issuerCert.pkijsCertificate.subject.typesAndValues[0].value.valueBlock.value;
    expect(subjectCertIssuerDn[0].value.valueBlock.value).toBe(issuerCn);
  });

  describe('Basic Constraints extension', () => {
    test('Extension should be included', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      });

      const extensions = cert.pkijsCertificate.extensions as ReadonlyArray<pkijs.Extension>;
      const matchingExtensions = extensions.filter(e => e.extnID === oids.BASIC_CONSTRAINTS);
      expect(matchingExtensions).toHaveLength(1);
    });

    test('Extension should be critical', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      });

      const extension = (cert.pkijsCertificate.extensions as ReadonlyArray<pkijs.Extension>)[0];
      expect(extension).toHaveProperty('critical', true);
    });

    test('CA flag should be false by default', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      });

      const extension = (cert.pkijsCertificate.extensions as ReadonlyArray<pkijs.Extension>)[0];
      const basicConstraintsAsn1 = deserializeDer(extension.extnValue.valueBlock.valueHex);
      const basicConstraints = new pkijs.BasicConstraints({ schema: basicConstraintsAsn1 });
      expect(basicConstraints).toHaveProperty('cA', false);
    });

    test('CA flag should be enabled if requested', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        isCA: true,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      });

      const extensions = cert.pkijsCertificate.extensions as ReadonlyArray<pkijs.Extension>;
      const matchingExtensions = extensions.filter(e => e.extnID === oids.BASIC_CONSTRAINTS);
      const extension = matchingExtensions[0];
      const basicConstraintsAsn1 = deserializeDer(extension.extnValue.valueBlock.valueHex);
      const basicConstraints = new pkijs.BasicConstraints({ schema: basicConstraintsAsn1 });
      expect(basicConstraints).toHaveProperty('cA', true);
    });

    test('Path length should be unspecified', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      });

      const extension = (cert.pkijsCertificate.extensions as ReadonlyArray<pkijs.Extension>)[0];
      const basicConstraintsAsn1 = deserializeDer(extension.extnValue.valueBlock.valueHex);
      const basicConstraints = new pkijs.BasicConstraints({ schema: basicConstraintsAsn1 });
      expect(basicConstraints).not.toHaveProperty('pathLenConstraint');
    });
  });

  describe('Authority Key Identifier extension', () => {
    test('should correspond to subject when self-issued', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      });

      const extensions = cert.pkijsCertificate.extensions || [];
      const matchingExtensions = extensions.filter(e => e.extnID === oids.AUTHORITY_KEY);
      expect(matchingExtensions).toHaveLength(1);
      const akiExtension = matchingExtensions[0];
      expect(akiExtension.critical).toBe(false);
      const akiExtensionAsn1 = deserializeDer(akiExtension.extnValue.valueBlock.valueHex);
      const akiExtensionRestored = new pkijs.AuthorityKeyIdentifier({
        schema: akiExtensionAsn1,
      });
      const keyIdBuffer = Buffer.from(akiExtensionRestored.keyIdentifier.valueBlock.valueHex);
      expect(keyIdBuffer.toString('hex')).toEqual(await getPublicKeyDigest(keyPair.publicKey));
    });

    test('should correspond to issuer key when different from subject', async () => {
      const issuerKeyPair = await generateRSAKeyPair();
      const issuerCert = await Certificate.issue({
        ...baseCertificateOptions,
        isCA: true,
        issuerPrivateKey: issuerKeyPair.privateKey,
        subjectPublicKey: issuerKeyPair.publicKey,
      });

      const subjectKeyPair = await generateRSAKeyPair();
      const subjectCert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: issuerCert,
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
      });

      const extensions = subjectCert.pkijsCertificate.extensions || [];
      const matchingExtensions = extensions.filter(e => e.extnID === oids.AUTHORITY_KEY);
      expect(matchingExtensions).toHaveLength(1);
      const akiExtension = matchingExtensions[0];
      expect(akiExtension.critical).toBe(false);
      const akiExtensionAsn1 = deserializeDer(akiExtension.extnValue.valueBlock.valueHex);
      const akiExtensionRestored = new pkijs.AuthorityKeyIdentifier({
        schema: akiExtensionAsn1,
      });
      const keyIdBuffer = Buffer.from(akiExtensionRestored.keyIdentifier.valueBlock.valueHex);
      expect(keyIdBuffer.toString('hex')).toEqual(
        await getPublicKeyDigest(issuerKeyPair.publicKey),
      );
    });
  });

  test('Subject Key Identifier extension should correspond to subject key', async () => {
    const issuerKeyPair = await generateRSAKeyPair();
    const issuerCert = await Certificate.issue({
      ...baseCertificateOptions,
      isCA: true,
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
    });

    const subjectKeyPair = await generateRSAKeyPair();
    const subjectCert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerCertificate: issuerCert,
      issuerPrivateKey: subjectKeyPair.privateKey,
      subjectPublicKey: subjectKeyPair.publicKey,
    });

    const extensions = subjectCert.pkijsCertificate.extensions || [];
    const matchingExtensions = extensions.filter(e => e.extnID === oids.SUBJECT_KEY);
    expect(matchingExtensions).toHaveLength(1);
    const skiExtension = matchingExtensions[0];
    expect(skiExtension.critical).toBe(false);
    const skiExtensionAsn1 = deserializeDer(skiExtension.extnValue.valueBlock.valueHex);
    expect(skiExtensionAsn1).toBeInstanceOf(asn1js.OctetString);
    // @ts-ignore
    const keyIdBuffer = Buffer.from(skiExtensionAsn1.valueBlock.valueHex);
    expect(keyIdBuffer.toString('hex')).toEqual(await getPublicKeyDigest(subjectKeyPair.publicKey));
  });
});

test('serialize() should return a DER-encoded buffer', async () => {
  const cert = await generateStubCert();

  const certDer = cert.serialize();

  const asn1Value = deserializeDer(certDer);
  const pkijsCert = new pkijs.Certificate({ schema: asn1Value });

  const subjectDnAttributes = pkijsCert.subject.typesAndValues;
  expect(subjectDnAttributes.length).toBe(1);
  expect(subjectDnAttributes[0].type).toBe(oids.COMMON_NAME);
  expect(subjectDnAttributes[0].value.valueBlock.value).toBe(cert.getAddress());

  const issuerDnAttributes = pkijsCert.issuer.typesAndValues;
  expect(issuerDnAttributes.length).toBe(1);
  expect(issuerDnAttributes[0].type).toBe(oids.COMMON_NAME);
  expect(issuerDnAttributes[0].value.valueBlock.value).toBe(cert.getAddress());
});

describe('getAddress()', () => {
  test('should return the address when found', async () => {
    const cert = await generateStubCert();

    const subjectDn = cert.pkijsCertificate.subject.typesAndValues;

    expect(cert.getAddress()).toEqual(subjectDn[0].value.valueBlock.value);
  });

  test('should error out when the address is not found', async () => {
    const cert = await generateStubCert();

    // tslint:disable-next-line:no-object-mutation
    cert.pkijsCertificate.subject.typesAndValues = [];

    expect(() => cert.getAddress()).toThrowWithMessage(
      CertificateError,
      'Could not find subject node address in certificate',
    );
  });
});

describe('validate()', () => {
  describe('X.509 certificate version', () => {
    test('it should accept version 3', async () => {
      const cert = await generateStubCert();
      // tslint:disable-next-line:no-object-mutation
      cert.pkijsCertificate.version = 2; // Versioning starts at 0

      cert.validate();
    });

    test('it should refuse versions other than 3', async () => {
      const cert = await generateStubCert();
      // tslint:disable-next-line:no-object-mutation
      cert.pkijsCertificate.version = 1;

      expect(() => cert.validate()).toThrowWithMessage(
        CertificateError,
        'Only X.509 v3 certificates are supported (got v2)',
      );
    });
  });
});

async function getPublicKeyDigest(publicKey: CryptoKey): Promise<string> {
  // @ts-ignore
  const publicKeyDer = await pkijsCrypto.exportKey('spki', publicKey);
  return sha256Hex(publicKeyDer);
}
