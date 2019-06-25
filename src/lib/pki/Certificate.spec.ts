import * as asn1js from 'asn1js';
import bufferToArrayBuffer from 'buffer-to-arraybuffer';
import { createHash } from 'crypto';
import * as jestDateMock from 'jest-date-mock';
import * as pkijs from 'pkijs';
import { generateRsaKeys } from '../crypto';
import Certificate from './Certificate';
import CertificateAttributes from './CertificateAttributes';
import CertificateError from './CertificateError';

const OID_COMMON_NAME = '2.5.4.3';

const futureDate = new Date();
futureDate.setDate(futureDate.getDate() + 1);

const cryptoEngine = pkijs.getCrypto();
if (cryptoEngine === undefined) {
  throw new Error('PKI.js crypto engine is undefined');
}

afterEach(() => {
  jest.restoreAllMocks();
  jestDateMock.clear();
});

describe('deserialize()', () => {
  test('should deserialize valid DER-encoded certificates', async () => {
    // Serialize manually just in this test to avoid depending on .serialize()
    const pkijsCert = (await generateStubCert()).pkijsCertificate;
    const certDer = pkijsCert.toSchema(true).toBER(false);

    const cert = Certificate.deserialize(Buffer.from(certDer));

    expect(cert.pkijsCertificate.subject.typesAndValues[0].type).toBe(
      pkijsCert.subject.typesAndValues[0].type
    );
    expect(
      cert.pkijsCertificate.subject.typesAndValues[0].value.valueBlock.value
    ).toBe(pkijsCert.subject.typesAndValues[0].value.valueBlock.value);
  });

  test('should error out with invalid DER values', () => {
    const invalidDer = Buffer.from('nope');
    expect(() => Certificate.deserialize(invalidDer)).toThrowWithMessage(
      CertificateError,
      'Certificate is not DER-encoded'
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
  test('should create a X.509 v3 certificate', async () => {
    const keyPair = await generateRsaKeys();
    const cert = await Certificate.issue(keyPair.privateKey, {
      serialNumber: 1,
      subjectPublicKey: keyPair.publicKey,
      validityEndDate: futureDate
    });

    // v3 is serialized as integer 2
    expect(cert.pkijsCertificate.version).toBe(0x2);
  });

  test('should import the public key into the certificate', async () => {
    const keyPair = await generateRsaKeys();
    spyOn(pkijs.PublicKeyInfo.prototype, 'importKey');
    await Certificate.issue(keyPair.privateKey, {
      serialNumber: 1,
      subjectPublicKey: keyPair.publicKey,
      validityEndDate: futureDate
    });

    expect(pkijs.PublicKeyInfo.prototype.importKey).toBeCalledTimes(1);
    expect(pkijs.PublicKeyInfo.prototype.importKey).toBeCalledWith(
      keyPair.publicKey
    );
  });

  test('should be signed with the specified private key', async () => {
    const { privateKey, publicKey } = await generateRsaKeys();
    spyOn(pkijs.Certificate.prototype, 'sign');
    await Certificate.issue(privateKey, {
      serialNumber: 1,
      subjectPublicKey: publicKey,
      validityEndDate: futureDate
    });

    expect(pkijs.Certificate.prototype.sign).toBeCalledTimes(1);
    expect(pkijs.Certificate.prototype.sign).toBeCalledWith(
      privateKey,
      ((privateKey.algorithm as RsaHashedKeyGenParams).hash as Algorithm).name
    );
  });

  test('should store the specified serial number', async () => {
    const keyPair = await generateRsaKeys();
    const serialNumber = 2019;
    const cert = await Certificate.issue(keyPair.privateKey, {
      serialNumber,
      subjectPublicKey: keyPair.publicKey,
      validityEndDate: futureDate
    });

    expect(cert.pkijsCertificate.serialNumber.valueBlock.valueDec).toBe(
      serialNumber
    );
  });

  test('should create a certificate valid from now by default', async () => {
    const keyPair = await generateRsaKeys();
    const now = new Date();
    jestDateMock.advanceTo(now);
    const cert = await Certificate.issue(keyPair.privateKey, {
      serialNumber: 1,
      subjectPublicKey: keyPair.publicKey,
      validityEndDate: futureDate
    });

    expect(cert.pkijsCertificate.notBefore.value).toEqual(now);
  });

  test('should honor a custom start validity date', async () => {
    const keyPair = await generateRsaKeys();
    const startDate = new Date(2019, 1, 1);
    const cert = await Certificate.issue(keyPair.privateKey, {
      serialNumber: 1,
      subjectPublicKey: keyPair.publicKey,
      validityEndDate: futureDate,
      validityStartDate: startDate
    });

    expect(cert.pkijsCertificate.notBefore.value).toBe(startDate);
  });

  test('should honor a custom end validity date', async () => {
    const keyPair = await generateRsaKeys();
    const cert = await Certificate.issue(keyPair.privateKey, {
      serialNumber: 1,
      subjectPublicKey: keyPair.publicKey,
      validityEndDate: futureDate
    });

    expect(cert.pkijsCertificate.notAfter.value).toBe(futureDate);
  });

  test('should not accept an end date before the start date', async () => {
    const keyPair = await generateRsaKeys();
    const attributes = {
      serialNumber: 1,
      subjectPublicKey: keyPair.publicKey,
      validityEndDate: new Date(2000, 1, 1)
    };
    await expect(
      Certificate.issue(keyPair.privateKey, attributes)
    ).rejects.toThrow('The end date must be later than the start date');
  });

  test('should set the subject CN to the private node address', async () => {
    const { privateKey, publicKey } = await generateRsaKeys();
    const cert = await Certificate.issue(privateKey, {
      serialNumber: 1,
      subjectPublicKey: publicKey,
      validityEndDate: futureDate
    });

    const publicKeyDer = Buffer.from(
      await cryptoEngine.exportKey('spki', publicKey)
    );
    const publicKeyHash = createHash('sha256')
      .update(publicKeyDer)
      .digest('hex');
    const subjectDnAttributes = cert.pkijsCertificate.subject.typesAndValues;
    expect(subjectDnAttributes.length).toBe(1);
    expect(subjectDnAttributes[0].type).toBe(OID_COMMON_NAME);
    expect(subjectDnAttributes[0].value.valueBlock.value).toBe(
      `0${publicKeyHash}`
    );
  });

  test('should set issuer DN to that of subject when self-issuing certificates', async () => {
    const subjectKeyPair = await generateRsaKeys();
    const cert = await Certificate.issue(subjectKeyPair.privateKey, {
      serialNumber: 1,
      subjectPublicKey: subjectKeyPair.publicKey,
      validityEndDate: futureDate
    });

    const subjectDn = cert.pkijsCertificate.subject.typesAndValues;
    const issuerDn = cert.pkijsCertificate.issuer.typesAndValues;
    expect(issuerDn.length).toBe(1);
    expect(issuerDn[0].type).toBe(OID_COMMON_NAME);
    expect(issuerDn[0].value.valueBlock.value).toBe(
      subjectDn[0].value.valueBlock.value
    );
  });

  test('should set issuer DN to that of CA', async () => {
    const issuerKeyPair = await generateRsaKeys();
    const issuerCert = await Certificate.issue(issuerKeyPair.privateKey, {
      serialNumber: 1,
      subjectPublicKey: issuerKeyPair.publicKey,
      validityEndDate: futureDate
    });

    const subjectKeyPair = await generateRsaKeys();
    const subjectCert = await Certificate.issue(
      subjectKeyPair.privateKey,
      {
        serialNumber: 1,
        subjectPublicKey: subjectKeyPair.publicKey,
        validityEndDate: futureDate
      },
      issuerCert
    );

    const subjectCertIssuerDn =
      subjectCert.pkijsCertificate.issuer.typesAndValues;
    expect(subjectCertIssuerDn.length).toBe(1);
    expect(subjectCertIssuerDn[0].type).toBe(OID_COMMON_NAME);
    const issuerCn =
      issuerCert.pkijsCertificate.subject.typesAndValues[0].value.valueBlock
        .value;
    expect(subjectCertIssuerDn[0].value.valueBlock.value).toBe(issuerCn);
  });
});

test('serialize() should return a DER-encoded buffer', async () => {
  const cert = await generateStubCert();

  const certDer = cert.serialize();

  const asn1 = asn1js.fromBER(bufferToArrayBuffer(certDer));
  expect(asn1.result).not.toBe(-1);
  const pkijsCert = new pkijs.Certificate({ schema: asn1.result });

  const subjectDnAttributes = pkijsCert.subject.typesAndValues;
  expect(subjectDnAttributes.length).toBe(1);
  expect(subjectDnAttributes[0].type).toBe(OID_COMMON_NAME);
  expect(subjectDnAttributes[0].value.valueBlock.value).toBe(cert.getAddress());

  const issuerDnAttributes = pkijsCert.issuer.typesAndValues;
  expect(issuerDnAttributes.length).toBe(1);
  expect(issuerDnAttributes[0].type).toBe(OID_COMMON_NAME);
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
      'Could not find subject node address in certificate'
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
        'Only X.509 v3 certificates are supported (got v2)'
      );
    });
  });
});

interface StubCertConfig {
  readonly attributes?: Partial<CertificateAttributes>;
  readonly issuerPrivateKey?: CryptoKey;
  readonly subjectPublicKey?: CryptoKey;
}

async function generateStubCert(
  config: StubCertConfig = {}
): Promise<Certificate> {
  const keyPair = await generateRsaKeys();
  return Certificate.issue(config.issuerPrivateKey || keyPair.privateKey, {
    serialNumber: 1,
    subjectPublicKey: config.subjectPublicKey || keyPair.publicKey,
    validityEndDate: futureDate,
    ...config.attributes
  });
}
