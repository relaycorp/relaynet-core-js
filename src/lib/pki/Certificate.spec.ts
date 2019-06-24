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

describe('deserialize', () => {
  test('should deserialize valid DER-encoded certificates', async () => {
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

  describe('Validation', () => {
    test.todo('X.509 certificates with version != 3 are invalid');
  });
});

describe('issue', () => {
  test('The X.509 certificate version should be 3', async () => {
    const keyPair = await generateRsaKeys();
    const cert = await Certificate.issue(keyPair.privateKey, {
      serialNumber: 1,
      subjectPublicKey: keyPair.publicKey,
      validityEndDate: futureDate
    });

    // v3 is serialized as integer 2
    expect(cert.pkijsCertificate.version).toBe(0x2);
  });

  test('The public key should be imported into the certificate', async () => {
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

  test('The certificate is signed with the specified private key', async () => {
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

  test('The serial number should be stored', async () => {
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

  test('The certificate is valid from now by default', async () => {
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

  test('The certificate start date should be customizable', async () => {
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

  test('The end date should be stored', async () => {
    const keyPair = await generateRsaKeys();
    const cert = await Certificate.issue(keyPair.privateKey, {
      serialNumber: 1,
      subjectPublicKey: keyPair.publicKey,
      validityEndDate: futureDate
    });

    expect(cert.pkijsCertificate.notAfter.value).toBe(futureDate);
  });

  test('The end date should not come before the start date', async () => {
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

  test('Subject CN should correspond to private node if public address is missing', async () => {
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

  test('Subject CN should contain public address if set', async () => {
    const { privateKey, publicKey } = await generateRsaKeys();
    const publicAddress = 'rng:gateway.redcross.org';
    const cert = await Certificate.issue(privateKey, {
      publicAddress,
      serialNumber: 1,
      subjectPublicKey: publicKey,
      validityEndDate: futureDate
    });

    const subjectDnAttributes = cert.pkijsCertificate.subject.typesAndValues;
    expect(subjectDnAttributes.length).toBe(1);
    expect(subjectDnAttributes[0].type).toBe(OID_COMMON_NAME);
    expect(subjectDnAttributes[0].value.valueBlock.value).toBe(publicAddress);
  });

  test('Issuer DN should fall back to that of subject when self-signed', async () => {
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

  test('Issuer DN should be stored', async () => {
    const issuerKeyPair = await generateRsaKeys();
    const issuerCn = 'rng:gateway.redcross.org';
    const issuerCert = await Certificate.issue(issuerKeyPair.privateKey, {
      publicAddress: issuerCn,
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

    const issuerDn = subjectCert.pkijsCertificate.issuer.typesAndValues;
    expect(issuerDn.length).toBe(1);
    expect(issuerDn[0].type).toBe(OID_COMMON_NAME);
    expect(issuerDn[0].value.valueBlock.value).toBe(issuerCn);
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

describe('getAddress', () => {
  const RELAYNET_NODE_ADDRESS = 'foo';

  test('should return the address when found', async () => {
    const cert = await generateStubCert({
      attributes: { publicAddress: RELAYNET_NODE_ADDRESS }
    });

    expect(cert.getAddress()).toEqual(RELAYNET_NODE_ADDRESS);
  });

  test('should error out when the address is not found', async () => {
    const cert = await generateStubCert({
      attributes: { publicAddress: RELAYNET_NODE_ADDRESS }
    });

    // tslint:disable-next-line:no-object-mutation
    cert.pkijsCertificate.subject.typesAndValues = [];

    expect(() => cert.getAddress()).toThrowWithMessage(
      CertificateError,
      'Could not find subject node address in certificate'
    );
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
