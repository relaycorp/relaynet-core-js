import * as asn1js from 'asn1js';
import bufferToArrayBuffer from 'buffer-to-arraybuffer';
import * as jestDateMock from 'jest-date-mock';
import * as pkijs from 'pkijs';

import {
  expectBuffersToEqual,
  generateStubCert,
  reSerializeCertificate,
  sha256Hex,
} from '../../_test_utils';
import * as oids from '../../oids';
import { derDeserialize, getPkijsCrypto } from '../_utils';
import {
  derSerializePublicKey,
  generateRSAKeyPair,
  getPrivateAddressFromIdentityKey,
} from '../keys';
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
});

describe('issue()', () => {
  const baseCertificateOptions = {
    commonName: 'the CN',
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

  test('should generate a positive serial number', async () => {
    let anySignFlipped = false;
    for (let index = 0; index < 10; index++) {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      });
      const serialNumberSerialized = new Uint8Array(
        cert.pkijsCertificate.serialNumber.valueBlock.valueHex,
      );
      if (serialNumberSerialized.length === 9) {
        expect(serialNumberSerialized[0]).toEqual(0);
        anySignFlipped = true;
      } else {
        expect(serialNumberSerialized).toHaveLength(8);
        expect(serialNumberSerialized[0]).toBeGreaterThan(0);
        expect(serialNumberSerialized[0]).toBeLessThanOrEqual(127);
      }
    }

    expect(anySignFlipped).toBeTrue();
  });

  test('should create a certificate valid from now by default', async () => {
    const now = new Date();
    now.setMilliseconds(1); // We need to check it's rounded down to the nearest second
    jestDateMock.advanceTo(now);

    const cert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
    });

    const expectedDate = new Date(now.getTime());
    expectedDate.setMilliseconds(0);
    expect(cert.startDate).toEqual(expectedDate);
  });

  test('should honor a custom start validity date', async () => {
    const startDate = new Date(2019, 1, 1, 1, 1, 1, 1);

    const cert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
      validityStartDate: startDate,
    });

    const expectedDate = new Date(startDate.getTime());
    expectedDate.setMilliseconds(0);
    expect(cert.startDate).toEqual(expectedDate);
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

    await expect(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: issuerCert,
        issuerPrivateKey: issuerKeyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      }),
    ).rejects.toEqual(
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

    await expect(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: issuerCert,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      }),
    ).rejects.toEqual(
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
    issuerCert.pkijsCertificate.extensions = (
      issuerCert.pkijsCertificate.extensions as ReadonlyArray<pkijs.Extension>
    ).filter((e) => e.extnID !== oids.BASIC_CONSTRAINTS);

    await expect(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: issuerCert,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      }),
    ).rejects.toEqual(
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

    await expect(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: issuerCert,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      }),
    ).rejects.toEqual(new CertificateError('Issuer is not a CA'));
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
    test('Extension should be included and marked as critical', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      });

      const extensions = cert.pkijsCertificate.extensions as ReadonlyArray<pkijs.Extension>;
      const matchingExtensions = extensions.filter((e) => e.extnID === oids.BASIC_CONSTRAINTS);
      expect(matchingExtensions).toHaveLength(1);
      expect(matchingExtensions[0]).toHaveProperty('critical', true);
    });

    test('CA flag should be false by default', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      });

      const basicConstraints = getBasicConstraintsExtension(cert);
      expect(basicConstraints).toHaveProperty('cA', false);
    });

    test('CA flag should be enabled if requested', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        isCA: true,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      });
      const basicConstraints = getBasicConstraintsExtension(cert);
      expect(basicConstraints).toHaveProperty('cA', true);
    });

    test('pathLenConstraint should be 0 by default', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
      });

      const basicConstraints = getBasicConstraintsExtension(cert);
      expect(basicConstraints).toHaveProperty('pathLenConstraint', 0);
    });

    test('pathLenConstraint can be set to a custom value <= 2', async () => {
      const pathLenConstraint = 2;
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: keyPair.privateKey,
        pathLenConstraint,
        subjectPublicKey: keyPair.publicKey,
      });

      const basicConstraints = getBasicConstraintsExtension(cert);
      expect(basicConstraints).toHaveProperty('pathLenConstraint', pathLenConstraint);
    });

    test('pathLenConstraint should not be greater than 2', async () => {
      await expect(
        Certificate.issue({
          ...baseCertificateOptions,
          issuerPrivateKey: keyPair.privateKey,
          pathLenConstraint: 3,
          subjectPublicKey: keyPair.publicKey,
        }),
      ).rejects.toEqual(new CertificateError('pathLenConstraint must be between 0 and 2 (got 3)'));
    });

    test('pathLenConstraint should not be negative', async () => {
      await expect(
        Certificate.issue({
          ...baseCertificateOptions,
          issuerPrivateKey: keyPair.privateKey,
          pathLenConstraint: -1,
          subjectPublicKey: keyPair.publicKey,
        }),
      ).rejects.toEqual(new CertificateError('pathLenConstraint must be between 0 and 2 (got -1)'));
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
      const matchingExtensions = extensions.filter((e) => e.extnID === oids.AUTHORITY_KEY);
      expect(matchingExtensions).toHaveLength(1);
      const akiExtension = matchingExtensions[0];
      expect(akiExtension.critical).toBe(false);
      const akiExtensionAsn1 = derDeserialize(akiExtension.extnValue.valueBlock.valueHex);
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
      const matchingExtensions = extensions.filter((e) => e.extnID === oids.AUTHORITY_KEY);
      expect(matchingExtensions).toHaveLength(1);
      const akiExtension = matchingExtensions[0];
      expect(akiExtension.critical).toBe(false);
      const akiExtensionAsn1 = derDeserialize(akiExtension.extnValue.valueBlock.valueHex);
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
    const matchingExtensions = extensions.filter((e) => e.extnID === oids.SUBJECT_KEY);
    expect(matchingExtensions).toHaveLength(1);
    const skiExtension = matchingExtensions[0];
    expect(skiExtension.critical).toBe(false);
    const skiExtensionAsn1 = derDeserialize(skiExtension.extnValue.valueBlock.valueHex);
    expect(skiExtensionAsn1).toBeInstanceOf(asn1js.OctetString);
    // @ts-ignore
    const keyIdBuffer = Buffer.from(skiExtensionAsn1.valueBlock.valueHex);
    expect(keyIdBuffer.toString('hex')).toEqual(await getPublicKeyDigest(subjectKeyPair.publicKey));
  });
});

test('serialize() should return a DER-encoded buffer', async () => {
  const cert = await generateStubCert();

  const certDer = cert.serialize();

  const asn1Value = derDeserialize(certDer);
  const pkijsCert = new pkijs.Certificate({ schema: asn1Value });

  const subjectDnAttributes = pkijsCert.subject.typesAndValues;
  expect(subjectDnAttributes.length).toBe(1);
  expect(subjectDnAttributes[0].type).toBe(oids.COMMON_NAME);
  expect(subjectDnAttributes[0].value.valueBlock.value).toBe(cert.getCommonName());

  const issuerDnAttributes = pkijsCert.issuer.typesAndValues;
  expect(issuerDnAttributes.length).toBe(1);
  expect(issuerDnAttributes[0].type).toBe(oids.COMMON_NAME);
  expect(issuerDnAttributes[0].value.valueBlock.value).toBe(cert.getCommonName());
});

test('startDate should return the start date', async () => {
  const cert = await generateStubCert();

  const expectedStartDate = cert.pkijsCertificate.notBefore.value;
  expect(cert.startDate).toEqual(expectedStartDate);
});

test('expiryDate should return the expiry date', async () => {
  const cert = await generateStubCert();

  const expectedExpiryDate = cert.pkijsCertificate.notAfter.value;
  expect(cert.expiryDate).toEqual(expectedExpiryDate);
});

test('getSerialNumber() should return the serial number as a buffer', async () => {
  const cert = await generateStubCert();

  const serialNumberBuffer = cert.getSerialNumber();
  expect(serialNumberBuffer).toEqual(
    Buffer.from(cert.pkijsCertificate.serialNumber.valueBlock.valueHex),
  );
});

test('getSerialNumberHex() should return the hex representation of serial number', async () => {
  const cert = await generateStubCert();

  const serialNumberHex = cert.getSerialNumberHex();
  expect(Buffer.from(serialNumberHex, 'hex')).toEqual(cert.getSerialNumber());
});

describe('getCommonName()', () => {
  test('should return the address when found', async () => {
    const cert = await generateStubCert();

    const subjectDn = cert.pkijsCertificate.subject.typesAndValues;

    expect(cert.getCommonName()).toEqual(subjectDn[0].value.valueBlock.value);
  });

  test('should error out when the address is not found', async () => {
    const cert = await generateStubCert();

    // tslint:disable-next-line:no-object-mutation
    cert.pkijsCertificate.subject.typesAndValues = [];

    expect(() => cert.getCommonName()).toThrowWithMessage(
      CertificateError,
      'Distinguished Name does not contain Common Name',
    );
  });
});

describe('calculateSubjectPrivateAddress', () => {
  test('Private node address should be returned', async () => {
    const nodeKeyPair = await generateRSAKeyPair();
    const nodeCertificate = await generateStubCert({
      issuerPrivateKey: nodeKeyPair.privateKey,
      subjectPublicKey: nodeKeyPair.publicKey,
    });

    await expect(nodeCertificate.calculateSubjectPrivateAddress()).resolves.toEqual(
      await getPrivateAddressFromIdentityKey(nodeKeyPair.publicKey),
    );
  });

  test('Computation should be cached', async () => {
    const nodeKeyPair = await generateRSAKeyPair();
    const nodeCertificate = await generateStubCert({
      issuerPrivateKey: nodeKeyPair.privateKey,
      subjectPublicKey: nodeKeyPair.publicKey,
    });
    const getPublicKeySpy = jest.spyOn(nodeCertificate, 'getPublicKey');

    const address = await nodeCertificate.calculateSubjectPrivateAddress();
    await expect(nodeCertificate.calculateSubjectPrivateAddress()).resolves.toEqual(address);

    expect(getPublicKeySpy).toBeCalledTimes(1);
  });
});

describe('getIssuerPrivateAddress', () => {
  test('Nothing should be output if there are no extensions', async () => {
    const certificate = await generateStubCert({});
    // tslint:disable-next-line:no-delete no-object-mutation
    delete certificate.pkijsCertificate.extensions;

    expect(certificate.getIssuerPrivateAddress()).toBeNull();
  });

  test('Nothing should be output if extension is missing', async () => {
    const certificate = await generateStubCert({});
    // tslint:disable-next-line:no-object-mutation
    certificate.pkijsCertificate.extensions = certificate.pkijsCertificate.extensions!.filter(
      (e) => e.extnID !== oids.AUTHORITY_KEY,
    );

    expect(certificate.getIssuerPrivateAddress()).toBeNull();
  });

  test('Private address of issuer should be output if extension is present', async () => {
    const issuerKeyPair = await generateRSAKeyPair();
    const issuerCertificate = reSerializeCertificate(
      await generateStubCert({
        attributes: { isCA: true },
        issuerPrivateKey: issuerKeyPair.privateKey,
        subjectPublicKey: issuerKeyPair.publicKey,
      }),
    );
    const certificate = await generateStubCert({
      issuerCertificate,
      issuerPrivateKey: issuerKeyPair.privateKey,
    });

    expect(certificate.getIssuerPrivateAddress()).toEqual(
      await issuerCertificate.calculateSubjectPrivateAddress(),
    );
  });
});

describe('isEqual', () => {
  test('Equal certificates should be reported as such', async () => {
    const cert1 = await generateStubCert();
    const cert2 = Certificate.deserialize(cert1.serialize());

    expect(cert1.isEqual(cert2)).toBeTrue();
  });

  test('Different certificates should be reported as such', async () => {
    const cert1 = await generateStubCert();
    const cert2 = await generateStubCert();

    expect(cert1.isEqual(cert2)).toBeFalse();
  });
});

describe('validate()', () => {
  test('Valid certificates should be accepted', async () => {
    const cert = await generateStubCert();

    cert.validate();
  });

  test('Certificate version other than 3 should be refused', async () => {
    const cert = await generateStubCert();
    // tslint:disable-next-line:no-object-mutation
    cert.pkijsCertificate.version = 1;

    expect(() => cert.validate()).toThrowWithMessage(
      CertificateError,
      'Only X.509 v3 certificates are supported (got v2)',
    );
  });

  test('Certificate not yet valid should not be accepted', async () => {
    const validityStartDate = new Date();
    validityStartDate.setMinutes(validityStartDate.getMinutes() + 5);
    const validityEndDate = new Date(validityStartDate);
    validityEndDate.setMinutes(validityEndDate.getMinutes() + 1);
    const cert = await generateStubCert({ attributes: { validityEndDate, validityStartDate } });

    expect(() => cert.validate()).toThrowWithMessage(
      CertificateError,
      'Certificate is not yet valid',
    );
  });

  test('Expired certificate should not be accepted', async () => {
    const validityEndDate = new Date();
    validityEndDate.setMinutes(validityEndDate.getMinutes() - 1);
    const validityStartDate = new Date(validityEndDate);
    validityStartDate.setMinutes(validityStartDate.getMinutes() - 1);
    const cert = await generateStubCert({ attributes: { validityEndDate, validityStartDate } });

    expect(() => cert.validate()).toThrowWithMessage(
      CertificateError,
      'Certificate already expired',
    );
  });
});

describe('getCertificationPath', () => {
  let stubTrustedCaPrivateKey: CryptoKey;
  let stubRootCa: Certificate;
  beforeAll(async () => {
    const trustedCaKeyPair = await generateRSAKeyPair();
    stubTrustedCaPrivateKey = trustedCaKeyPair.privateKey;
    stubRootCa = reSerializeCertificate(
      await generateStubCert({
        attributes: { isCA: true },
        issuerPrivateKey: trustedCaKeyPair.privateKey,
        subjectPublicKey: trustedCaKeyPair.publicKey,
      }),
    );
  });

  test('Cert issued by trusted cert should be trusted', async () => {
    const cert = reSerializeCertificate(
      await generateStubCert({
        issuerCertificate: stubRootCa,
        issuerPrivateKey: stubTrustedCaPrivateKey,
      }),
    );

    await expect(cert.getCertificationPath([], [stubRootCa])).resolves.toEqual([cert, stubRootCa]);
  });

  test('Cert not issued by trusted cert should not be trusted', async () => {
    const cert = await generateStubCert();

    await expect(cert.getCertificationPath([], [stubRootCa])).rejects.toEqual(
      new CertificateError('No valid certificate paths found'),
    );
  });

  test('Expired certificate should not be trusted', async () => {
    const validityEndDate = new Date();
    validityEndDate.setMinutes(validityEndDate.getMinutes() - 1);
    const validityStartDate = new Date(validityEndDate);
    validityStartDate.setMinutes(validityStartDate.getMinutes() - 1);
    const cert = await generateStubCert({ attributes: { validityEndDate, validityStartDate } });

    await expect(cert.getCertificationPath([], [stubRootCa])).rejects.toEqual(
      new CertificateError('No valid certificate paths found'),
    );
  });

  test('Cert issued by untrusted intermediate should be trusted if root is trusted', async () => {
    const intermediateCaKeyPair = await generateRSAKeyPair();
    const intermediateCaCert = reSerializeCertificate(
      await generateStubCert({
        attributes: { isCA: true },
        issuerCertificate: stubRootCa,
        issuerPrivateKey: stubTrustedCaPrivateKey,
        subjectPublicKey: intermediateCaKeyPair.publicKey,
      }),
    );

    const cert = reSerializeCertificate(
      await generateStubCert({
        issuerCertificate: intermediateCaCert,
        issuerPrivateKey: intermediateCaKeyPair.privateKey,
      }),
    );

    await expect(cert.getCertificationPath([intermediateCaCert], [stubRootCa])).resolves.toEqual([
      cert,
      intermediateCaCert,
      stubRootCa,
    ]);
  });

  test('Cert issued by trusted intermediate CA should be trusted', async () => {
    const intermediateCaKeyPair = await generateRSAKeyPair();
    const intermediateCaCert = reSerializeCertificate(
      await generateStubCert({
        attributes: { isCA: true },
        issuerCertificate: stubRootCa,
        issuerPrivateKey: stubTrustedCaPrivateKey,
        subjectPublicKey: intermediateCaKeyPair.publicKey,
      }),
    );

    const cert = reSerializeCertificate(
      await generateStubCert({
        issuerCertificate: intermediateCaCert,
        issuerPrivateKey: intermediateCaKeyPair.privateKey,
      }),
    );

    await expect(cert.getCertificationPath([], [intermediateCaCert])).resolves.toEqual([
      cert,
      intermediateCaCert,
    ]);
  });

  test('Cert issued by untrusted intermediate CA should not be trusted', async () => {
    const untrustedIntermediateCaKeyPair = await generateRSAKeyPair();
    const untrustedIntermediateCaCert = await generateStubCert({
      attributes: { isCA: true },
      issuerPrivateKey: untrustedIntermediateCaKeyPair.privateKey,
      subjectPublicKey: untrustedIntermediateCaKeyPair.publicKey,
    });

    const cert = reSerializeCertificate(
      await generateStubCert({
        issuerCertificate: untrustedIntermediateCaCert,
        issuerPrivateKey: untrustedIntermediateCaKeyPair.privateKey,
      }),
    );

    await expect(
      cert.getCertificationPath(
        [reSerializeCertificate(untrustedIntermediateCaCert)],
        [stubRootCa],
      ),
    ).rejects.toEqual(new CertificateError('No valid certificate paths found'));
  });

  test('Including trusted intermediate CA should not make certificate trusted', async () => {
    const intermediateCaKeyPair = await generateRSAKeyPair();
    const trustedIntermediateCaCert = await generateStubCert({
      attributes: { isCA: true },
      issuerPrivateKey: intermediateCaKeyPair.privateKey,
      subjectPublicKey: intermediateCaKeyPair.publicKey,
    });

    const cert = await generateStubCert();

    await expect(
      cert.getCertificationPath([trustedIntermediateCaCert], [stubRootCa]),
    ).rejects.toEqual(new CertificateError('No valid certificate paths found'));
  });

  test('Root certificate should be ignored if passed as intermediate unnecessarily', async () => {
    const intermediateCaKeyPair = await generateRSAKeyPair();
    const intermediateCaCert = reSerializeCertificate(
      await generateStubCert({
        attributes: { isCA: true },
        issuerCertificate: stubRootCa,
        issuerPrivateKey: stubTrustedCaPrivateKey,
        subjectPublicKey: intermediateCaKeyPair.publicKey,
      }),
    );

    const cert = reSerializeCertificate(
      await generateStubCert({
        issuerCertificate: intermediateCaCert,
        issuerPrivateKey: intermediateCaKeyPair.privateKey,
      }),
    );

    await expect(
      cert.getCertificationPath([intermediateCaCert, stubRootCa], [intermediateCaCert]),
    ).resolves.toEqual([cert, intermediateCaCert]);
  });
});

test('getPublicKey should return the subject public key', async () => {
  const subjectKeyPair = await generateRSAKeyPair();
  const cert = await generateStubCert({
    issuerPrivateKey: subjectKeyPair.privateKey,
    subjectPublicKey: subjectKeyPair.publicKey,
  });

  const publicKey = await cert.getPublicKey();

  expectBuffersToEqual(
    await derSerializePublicKey(publicKey),
    await derSerializePublicKey(subjectKeyPair.publicKey),
  );
});

function getBasicConstraintsExtension(cert: Certificate): pkijs.BasicConstraints {
  const extensions = cert.pkijsCertificate.extensions as ReadonlyArray<pkijs.Extension>;
  const matchingExtensions = extensions.filter((e) => e.extnID === oids.BASIC_CONSTRAINTS);
  const extension = matchingExtensions[0];
  const basicConstraintsAsn1 = derDeserialize(extension.extnValue.valueBlock.valueHex);
  return new pkijs.BasicConstraints({ schema: basicConstraintsAsn1 });
}

async function getPublicKeyDigest(publicKey: CryptoKey): Promise<string> {
  // @ts-ignore
  const publicKeyDer = await pkijsCrypto.exportKey('spki', publicKey);
  return sha256Hex(publicKeyDer);
}
