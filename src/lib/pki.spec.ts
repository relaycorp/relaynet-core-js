import * as jestDateMock from 'jest-date-mock';
import * as pkijs from 'pkijs';

import { expectPromiseToReject, generateStubCert, getMockContext, sha256Hex } from './_test_utils';
import { derSerializePublicKey, generateRSAKeyPair } from './crypto_wrappers/keys';
import Certificate from './crypto_wrappers/x509/Certificate';
import CertificateOptions from './crypto_wrappers/x509/CertificateOptions';
import {
  DHCertificateError,
  issueInitialDHKeyCertificate,
  issueNodeCertificate,
  NodeCertificateOptions,
} from './pki';

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

  test('Certificate should honor the specified options', async () => {
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

    const publicKeyDer = await derSerializePublicKey(publicKey);
    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions).toHaveProperty('commonName', `0${sha256Hex(publicKeyDer)}`);
  });

  test('Certificate should be marked as CA by default', async () => {
    await issueNodeCertificate(baseCertificateOptions);

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions).toHaveProperty('isCA', true);
  });

  test('Certificate can be marked as not a CA', async () => {
    await issueNodeCertificate({ ...baseCertificateOptions, isCA: false });

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions).toHaveProperty('isCA', false);
  });
});

describe('issueInitialDHKeyCertificate', () => {
  const MAX_VALIDITY_DAYS = 60;

  const stubFutureDate = new Date(2019, 1, 1);
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
    const dhCertificate = await issueInitialDHKeyCertificate({
      dhPublicKey: stubSubjectKeyPair.publicKey,
      nodeCertificate: stubNodeCertificate,
      nodePrivateKey: stubNodeKeyPair.privateKey,
    });

    expect(dhCertificate).toBe(stubCertificate);
  });

  test('Subject name should be that of the node', async () => {
    await issueInitialDHKeyCertificate({
      dhPublicKey: stubSubjectKeyPair.publicKey,
      nodeCertificate: stubNodeCertificate,
      nodePrivateKey: stubNodeKeyPair.privateKey,
    });

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.commonName).toEqual(stubNodeCertificate.getCommonName());
  });

  test('Subject key should be the one specified', async () => {
    await issueInitialDHKeyCertificate({
      dhPublicKey: stubSubjectKeyPair.publicKey,
      nodeCertificate: stubNodeCertificate,
      nodePrivateKey: stubNodeKeyPair.privateKey,
    });

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.subjectPublicKey).toBe(stubSubjectKeyPair.publicKey);
  });

  test('Issuer certificate should be that of the node', async () => {
    await issueInitialDHKeyCertificate({
      dhPublicKey: stubSubjectKeyPair.publicKey,
      nodeCertificate: stubNodeCertificate,
      nodePrivateKey: stubNodeKeyPair.privateKey,
    });

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.issuerCertificate).toBe(stubNodeCertificate);
  });

  test('Issuer private key should be that of the node', async () => {
    await issueInitialDHKeyCertificate({
      dhPublicKey: stubSubjectKeyPair.publicKey,
      nodeCertificate: stubNodeCertificate,
      nodePrivateKey: stubNodeKeyPair.privateKey,
    });

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.issuerPrivateKey).toBe(stubNodeKeyPair.privateKey);
  });

  test('Serial number should be generated if unset', async () => {
    await issueInitialDHKeyCertificate({
      dhPublicKey: stubSubjectKeyPair.publicKey,
      nodeCertificate: stubNodeCertificate,
      nodePrivateKey: stubNodeKeyPair.privateKey,
    });

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions).toHaveProperty('serialNumber', undefined);
  });

  test('Serial number should be the one specified if one was set', async () => {
    const serialNumber = 42;
    await issueInitialDHKeyCertificate({
      dhPublicKey: stubSubjectKeyPair.publicKey,
      nodeCertificate: stubNodeCertificate,
      nodePrivateKey: stubNodeKeyPair.privateKey,
      serialNumber,
    });

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.serialNumber).toEqual(serialNumber);
  });

  describe('Validity dates', () => {
    test('Start date should default to current date', async () => {
      const stubCurrentDate = new Date(2019, 1, 1);

      jestDateMock.advanceTo(stubCurrentDate);
      await issueInitialDHKeyCertificate({
        dhPublicKey: stubSubjectKeyPair.publicKey,
        nodeCertificate: stubNodeCertificate,
        nodePrivateKey: stubNodeKeyPair.privateKey,
      });

      const certificateOptions = getCertificateIssueCallOptions();
      expect(certificateOptions.validityStartDate).toEqual(stubCurrentDate);
    });

    test('Custom start date should be honored', async () => {
      const customStartDate = new Date(stubFutureDate);
      customStartDate.setDate(customStartDate.getDate() - 1);

      jestDateMock.advanceTo(customStartDate.getTime() - 3_600_000);
      await issueInitialDHKeyCertificate({
        dhPublicKey: stubSubjectKeyPair.publicKey,
        nodeCertificate: stubNodeCertificate,
        nodePrivateKey: stubNodeKeyPair.privateKey,
        validityEndDate: stubFutureDate,
        validityStartDate: customStartDate,
      });

      const certificateOptions = getCertificateIssueCallOptions();
      expect(certificateOptions.validityStartDate).toEqual(customStartDate);
    });

    test(`End date should default to 30 days from start date`, async () => {
      const stubCurrentDate = new Date(2019, 1, 1);

      jestDateMock.advanceTo(stubCurrentDate);
      await issueInitialDHKeyCertificate({
        dhPublicKey: stubSubjectKeyPair.publicKey,
        nodeCertificate: stubNodeCertificate,
        nodePrivateKey: stubNodeKeyPair.privateKey,
      });

      const expectedEndDate = new Date(stubCurrentDate);
      expectedEndDate.setDate(expectedEndDate.getDate() + 30);

      const certificateOptions = getCertificateIssueCallOptions();
      expect(certificateOptions.validityEndDate).toEqual(expectedEndDate);
    });

    test('Custom end date should be honored', async () => {
      await issueInitialDHKeyCertificate({
        dhPublicKey: stubSubjectKeyPair.publicKey,
        nodeCertificate: stubNodeCertificate,
        nodePrivateKey: stubNodeKeyPair.privateKey,
        validityEndDate: stubFutureDate,
      });

      const certificateOptions = getCertificateIssueCallOptions();
      expect(certificateOptions.validityEndDate).toEqual(stubFutureDate);
    });

    test(`Certificate should not be valid for over ${MAX_VALIDITY_DAYS} days`, async () => {
      const startDate = new Date(stubFutureDate);
      startDate.setDate(stubFutureDate.getDate() - MAX_VALIDITY_DAYS);
      startDate.setMilliseconds(stubFutureDate.getMilliseconds() - 1);

      await expectPromiseToReject(
        issueInitialDHKeyCertificate({
          dhPublicKey: stubSubjectKeyPair.publicKey,
          nodeCertificate: stubNodeCertificate,
          nodePrivateKey: stubNodeKeyPair.privateKey,
          validityEndDate: stubFutureDate,
          validityStartDate: startDate,
        }),
        new DHCertificateError(`DH key may not be valid for more than ${MAX_VALIDITY_DAYS} days`),
      );
    });
  });

  test('Subject should not be marked as CA in Basic Constraints extension', async () => {
    await issueInitialDHKeyCertificate({
      dhPublicKey: stubSubjectKeyPair.publicKey,
      nodeCertificate: stubNodeCertificate,
      nodePrivateKey: stubNodeKeyPair.privateKey,
    });

    const certificateOptions = getCertificateIssueCallOptions();
    expect(certificateOptions.isCA).toBeFalse();
  });
});

function getCertificateIssueCallOptions(): CertificateOptions {
  expect(Certificate.issue).toBeCalledTimes(1);
  const certificateIssueCall = getMockContext(Certificate.issue).calls[0];
  return certificateIssueCall[0];
}
