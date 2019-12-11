import * as jestDateMock from 'jest-date-mock';
import * as pkijs from 'pkijs';

import { generateStubCert, getMockContext, sha256Hex } from './_test_utils';
import { getPkijsCrypto } from './crypto_wrappers/_utils';
import { generateRSAKeyPair } from './crypto_wrappers/keyGenerators';
import Certificate from './crypto_wrappers/x509/Certificate';
import CertificateOptions from './crypto_wrappers/x509/CertificateOptions';
import {
  issueInitialDHKeyCertificate,
  issueNodeCertificate,
  NodeCertificateOptions,
} from './nodes';

const pkijsCrypto = getPkijsCrypto();

// tslint:disable-next-line:no-let
let stubSubjectKeyPair: CryptoKeyPair;
beforeAll(async () => {
  stubSubjectKeyPair = await generateRSAKeyPair();
});

const stubCertificate: Certificate = new Certificate(new pkijs.Certificate());
beforeEach(() => {
  jest.spyOn(Certificate, 'issue').mockResolvedValueOnce(Promise.resolve(stubCertificate));
});

describe('issueNodeCertificate', () => {
  // tslint:disable-next-line:no-let
  let baseCertificateOptions: NodeCertificateOptions;

  beforeAll(async () => {
    baseCertificateOptions = {
      issuerPrivateKey: stubSubjectKeyPair.privateKey,
      serialNumber: 1,
      subjectPublicKey: stubSubjectKeyPair.publicKey,
      validityEndDate: new Date(),
    };
  });

  test('Certificate should be a valid X.509 certificate', async () => {
    const certificate = await issueNodeCertificate(baseCertificateOptions);

    expect(certificate).toBe(stubCertificate);
  });

  test('Certificate should be issued with the original options', async () => {
    await issueNodeCertificate(baseCertificateOptions);

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions).toMatchObject(baseCertificateOptions);
  });

  test('Certificate should have its private address as its Common Name (CN)', async () => {
    const { publicKey } = await generateRSAKeyPair();

    await issueNodeCertificate({
      ...baseCertificateOptions,
      subjectPublicKey: publicKey,
    });

    const publicKeyDer = await pkijsCrypto.exportKey('spki', publicKey);
    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions).toHaveProperty('commonName', `0${sha256Hex(publicKeyDer)}`);
  });
});

describe('issueInitialDHKeyCertificate', () => {
  const stubFutureDate = new Date();
  stubFutureDate.setDate(stubFutureDate.getDate() + 1);

  // tslint:disable-next-line:no-let
  let stubNodeKeyPair: CryptoKeyPair;
  // tslint:disable-next-line:no-let
  let stubNodeCertificate: Certificate;
  beforeAll(async () => {
    stubNodeKeyPair = await generateRSAKeyPair();
    stubNodeCertificate = await generateStubCert({
      attributes: { serialNumber: 0 },
      issuerPrivateKey: stubNodeKeyPair.privateKey,
      subjectPublicKey: stubNodeKeyPair.publicKey,
    });
  });

  afterEach(() => {
    jestDateMock.clear();
  });

  test('Certificate should be a valid X.509 certificate', async () => {
    const dhCertificate = await issueInitialDHKeyCertificate(
      stubSubjectKeyPair.publicKey,
      stubNodeKeyPair.privateKey,
      stubNodeCertificate,
      1,
      stubFutureDate,
    );

    expect(dhCertificate).toBe(stubCertificate);
  });

  test('Subject name should be that of the node', async () => {
    await issueInitialDHKeyCertificate(
      stubSubjectKeyPair.publicKey,
      stubNodeKeyPair.privateKey,
      stubNodeCertificate,
      1,
      stubFutureDate,
    );

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.commonName).toEqual(stubNodeCertificate.getCommonName());
  });

  test('Subject key should be the one specified', async () => {
    await issueInitialDHKeyCertificate(
      stubSubjectKeyPair.publicKey,
      stubNodeKeyPair.privateKey,
      stubNodeCertificate,
      1,
      stubFutureDate,
    );

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.subjectPublicKey).toBe(stubSubjectKeyPair.publicKey);
  });

  test('Issuer certificate should be that of the node', async () => {
    await issueInitialDHKeyCertificate(
      stubSubjectKeyPair.publicKey,
      stubNodeKeyPair.privateKey,
      stubNodeCertificate,
      1,
      stubFutureDate,
    );

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.issuerCertificate).toBe(stubNodeCertificate);
  });

  test('Issuer private key should be that of the node', async () => {
    await issueInitialDHKeyCertificate(
      stubSubjectKeyPair.publicKey,
      stubNodeKeyPair.privateKey,
      stubNodeCertificate,
      1,
      stubFutureDate,
    );

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.issuerPrivateKey).toBe(stubNodeKeyPair.privateKey);
  });

  test('Serial number should be the one specified', async () => {
    const serialNumber = 42;
    await issueInitialDHKeyCertificate(
      stubSubjectKeyPair.publicKey,
      stubNodeKeyPair.privateKey,
      stubNodeCertificate,
      serialNumber,
      stubFutureDate,
    );

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.serialNumber).toEqual(serialNumber);
  });

  test('Start date should default to current date', async () => {
    const stubCurrentDate = new Date(2019, 1, 1);

    jestDateMock.advanceTo(stubCurrentDate);
    await issueInitialDHKeyCertificate(
      stubSubjectKeyPair.publicKey,
      stubNodeKeyPair.privateKey,
      stubNodeCertificate,
      1,
      stubFutureDate,
    );

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.validityStartDate).toEqual(stubCurrentDate);
  });

  test('Custom start date should be honored', async () => {
    const customStartDate = new Date(2019, 1, 1);

    jestDateMock.advanceTo(customStartDate.getTime() - 3_600_000);
    await issueInitialDHKeyCertificate(
      stubSubjectKeyPair.publicKey,
      stubNodeKeyPair.privateKey,
      stubNodeCertificate,
      1,
      stubFutureDate,
      customStartDate,
    );

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.validityStartDate).toEqual(customStartDate);
  });

  test('End date should be the one specified', async () => {
    await issueInitialDHKeyCertificate(
      stubSubjectKeyPair.publicKey,
      stubNodeKeyPair.privateKey,
      stubNodeCertificate,
      1,
      stubFutureDate,
    );

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.validityEndDate).toEqual(stubFutureDate);
  });

  test('Subject should not be marked as CA in Basic Constraints extension', async () => {
    await issueInitialDHKeyCertificate(
      stubSubjectKeyPair.publicKey,
      stubNodeKeyPair.privateKey,
      stubNodeCertificate,
      1,
      stubFutureDate,
    );

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.isCA).toBeFalse();
  });
});

function getCertificateIssueCallOptions(): CertificateOptions {
  expect(Certificate.issue).toBeCalledTimes(1);
  const certificateIssueCall = getMockContext(Certificate.issue).calls[0];
  return certificateIssueCall[0];
}
