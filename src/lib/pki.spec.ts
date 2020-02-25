// tslint:disable:no-let

import * as jestDateMock from 'jest-date-mock';
import * as pkijs from 'pkijs';

import { expectPromiseToReject, generateStubCert } from './_test_utils';
import { generateRSAKeyPair, getPublicKeyDigestHex } from './crypto_wrappers/keys';
import BasicCertificateIssuanceOptions from './crypto_wrappers/x509/BasicCertificateIssuanceOptions';
import Certificate from './crypto_wrappers/x509/Certificate';
import {
  DeliveryAuthorizationIssuanceOptions,
  DHCertificateError,
  DHKeyCertificateOptions,
  GatewayCertificateIssuanceOptions,
  issueDeliveryAuthorization,
  issueEndpointCertificate,
  issueGatewayCertificate,
  issueInitialDHKeyCertificate,
} from './pki';

let stubSubjectKeyPair: CryptoKeyPair;
let stubCertificate: Certificate;
beforeAll(async () => {
  stubSubjectKeyPair = await generateRSAKeyPair();
  stubCertificate = await generateStubCert({
    issuerPrivateKey: stubSubjectKeyPair.privateKey,
    subjectPublicKey: stubSubjectKeyPair.publicKey,
  });
});

const mockCertificateIssue = jest.spyOn(Certificate, 'issue');
beforeEach(() => {
  mockCertificateIssue.mockReset();
  mockCertificateIssue.mockResolvedValue(Promise.resolve(stubCertificate));
});
afterAll(() => {
  mockCertificateIssue.mockRestore();
});

let basicCertificateOptions: BasicCertificateIssuanceOptions;
beforeAll(async () => {
  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  basicCertificateOptions = {
    issuerPrivateKey: stubSubjectKeyPair.privateKey,
    subjectPublicKey: stubSubjectKeyPair.publicKey,
    validityEndDate: tomorrow,
    validityStartDate: new Date(),
  };
});

describe('issueGatewayCertificate', () => {
  let minimalCertificateOptions: GatewayCertificateIssuanceOptions;
  beforeAll(() => {
    minimalCertificateOptions = {
      issuerPrivateKey: stubSubjectKeyPair.privateKey,
      subjectPublicKey: stubSubjectKeyPair.publicKey,
      validityEndDate: new Date(),
    };
  });

  test('Certificate should be a valid X.509 certificate', async () => {
    const certificate = await issueGatewayCertificate(minimalCertificateOptions);

    expect(certificate).toBe(stubCertificate);
  });

  test('Certificate should honor all the basic options', async () => {
    await issueGatewayCertificate({ ...minimalCertificateOptions, ...basicCertificateOptions });

    expect(mockCertificateIssue.mock.calls[0][0]).toMatchObject(basicCertificateOptions);
  });

  test('Certificate should have its private address as its Common Name (CN)', async () => {
    await issueGatewayCertificate(minimalCertificateOptions);

    expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty(
      'commonName',
      `0${await getPublicKeyDigestHex(stubSubjectKeyPair.publicKey)}`,
    );
  });

  test('Subject should be marked as CA', async () => {
    await issueGatewayCertificate(minimalCertificateOptions);

    expect(mockCertificateIssue).toBeCalledTimes(1);
    expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('isCA', true);
  });

  test('pathLenConstraint should be 2 if self-issued', async () => {
    await issueGatewayCertificate(minimalCertificateOptions);

    expect(mockCertificateIssue).toBeCalledTimes(1);
    expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('pathLenConstraint', 2);
  });

  test('pathLenConstraint should be 1 if issued by another gateway', async () => {
    await issueGatewayCertificate({
      ...minimalCertificateOptions,
      issuerCertificate: new Certificate(new pkijs.Certificate()),
    });

    expect(mockCertificateIssue).toBeCalledTimes(1);
    expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('pathLenConstraint', 1);
  });
});

describe('issueEndpointCertificate', () => {
  let minimalCertificateOptions: GatewayCertificateIssuanceOptions;
  beforeAll(() => {
    minimalCertificateOptions = {
      issuerPrivateKey: stubSubjectKeyPair.privateKey,
      subjectPublicKey: stubSubjectKeyPair.publicKey,
      validityEndDate: new Date(),
    };
  });

  test('Certificate should be a valid X.509 certificate', async () => {
    const certificate = await issueEndpointCertificate(minimalCertificateOptions);

    expect(certificate).toBe(stubCertificate);
  });

  test('Certificate should honor all the basic options', async () => {
    await issueEndpointCertificate({ ...minimalCertificateOptions, ...basicCertificateOptions });

    expect(mockCertificateIssue.mock.calls[0][0]).toMatchObject(basicCertificateOptions);
  });

  test('Certificate should have its private address as its Common Name (CN)', async () => {
    await issueEndpointCertificate(minimalCertificateOptions);

    expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty(
      'commonName',
      `0${await getPublicKeyDigestHex(stubSubjectKeyPair.publicKey)}`,
    );
  });

  test('Certificate can be self-issued', async () => {
    expect(minimalCertificateOptions).not.toHaveProperty('issuerCertificate');

    await issueEndpointCertificate(minimalCertificateOptions);
  });

  test('Certificate can be issued by a gateway', async () => {
    const gatewayCertificate = new Certificate(new pkijs.Certificate());
    await issueEndpointCertificate({
      ...minimalCertificateOptions,
      issuerCertificate: gatewayCertificate,
    });

    expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty(
      'issuerCertificate',
      gatewayCertificate,
    );
  });

  test('Subject should be marked as CA', async () => {
    await issueEndpointCertificate(minimalCertificateOptions);

    expect(mockCertificateIssue).toBeCalledTimes(1);
    expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('isCA', true);
  });

  test('pathLenConstraint should be 0', async () => {
    await issueEndpointCertificate(minimalCertificateOptions);

    expect(mockCertificateIssue).toBeCalledTimes(1);
    expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('pathLenConstraint', 0);
  });
});

describe('issueDeliveryAuthorization', () => {
  let minimalCertificateOptions: DeliveryAuthorizationIssuanceOptions;
  beforeAll(async () => {
    const authorizerKeyPair = await generateRSAKeyPair();
    minimalCertificateOptions = {
      issuerCertificate: await generateStubCert({
        attributes: { isCA: true },
        issuerPrivateKey: authorizerKeyPair.privateKey,
        subjectPublicKey: authorizerKeyPair.publicKey,
      }),
      issuerPrivateKey: authorizerKeyPair.privateKey,
      subjectPublicKey: stubSubjectKeyPair.publicKey,
      validityEndDate: new Date(),
    };
  });

  test('Certificate should be a valid X.509 certificate', async () => {
    const certificate = await issueDeliveryAuthorization(minimalCertificateOptions);

    expect(certificate).toBe(stubCertificate);
  });

  test('Certificate should honor all the basic options', async () => {
    await issueDeliveryAuthorization({ ...minimalCertificateOptions, ...basicCertificateOptions });

    expect(mockCertificateIssue.mock.calls[0][0]).toMatchObject(basicCertificateOptions);
  });

  test('Certificate should have its private address as its Common Name (CN)', async () => {
    await issueDeliveryAuthorization(minimalCertificateOptions);

    expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty(
      'commonName',
      `0${await getPublicKeyDigestHex(stubSubjectKeyPair.publicKey)}`,
    );
  });

  test('Subject should not be marked as CA', async () => {
    await issueDeliveryAuthorization(minimalCertificateOptions);

    expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('isCA', false);
  });

  test('pathLenConstraint should be 0', async () => {
    await issueDeliveryAuthorization(minimalCertificateOptions);

    expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('pathLenConstraint', 0);
  });
});

describe('issueInitialDHKeyCertificate', () => {
  const MAX_VALIDITY_DAYS = 60;

  const stubFutureDate = new Date(2019, 1, 1);
  stubFutureDate.setDate(stubFutureDate.getDate() + 1);

  let baseIssuanceOptions: DHKeyCertificateOptions;
  let stubNodeKeyPair: CryptoKeyPair;
  let stubNodeCertificate: Certificate;
  beforeAll(async () => {
    stubNodeKeyPair = await generateRSAKeyPair();
    stubNodeCertificate = await generateStubCert({
      issuerPrivateKey: stubNodeKeyPair.privateKey,
      subjectPublicKey: stubNodeKeyPair.publicKey,
    });
    baseIssuanceOptions = {
      issuerCertificate: stubNodeCertificate,
      issuerPrivateKey: stubNodeKeyPair.privateKey,
      subjectPublicKey: stubSubjectKeyPair.publicKey,
      validityEndDate: stubFutureDate,
    };
  });

  afterEach(() => {
    jestDateMock.clear();
  });

  test('Certificate should be a valid X.509 certificate', async () => {
    const dhCertificate = await issueInitialDHKeyCertificate(baseIssuanceOptions);

    expect(dhCertificate).toBe(stubCertificate);
  });

  test('Subject name should be that of the node', async () => {
    await issueInitialDHKeyCertificate(baseIssuanceOptions);

    expect(mockCertificateIssue.mock.calls[0][0].commonName).toEqual(
      stubNodeCertificate.getCommonName(),
    );
  });

  test('Subject key should be the one specified', async () => {
    await issueInitialDHKeyCertificate(baseIssuanceOptions);

    expect(mockCertificateIssue.mock.calls[0][0].subjectPublicKey).toBe(
      stubSubjectKeyPair.publicKey,
    );
  });

  test('Issuer certificate should be that of the node', async () => {
    await issueInitialDHKeyCertificate(baseIssuanceOptions);

    expect(mockCertificateIssue.mock.calls[0][0].issuerCertificate).toBe(stubNodeCertificate);
  });

  test('Issuer private key should be that of the node', async () => {
    await issueInitialDHKeyCertificate(baseIssuanceOptions);

    expect(mockCertificateIssue.mock.calls[0][0].issuerPrivateKey).toBe(stubNodeKeyPair.privateKey);
  });

  test('Serial number should be generated if unset', async () => {
    await issueInitialDHKeyCertificate(baseIssuanceOptions);

    expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('serialNumber', undefined);
  });

  describe('Validity dates', () => {
    test('Start date should default to current date', async () => {
      await issueInitialDHKeyCertificate(baseIssuanceOptions);

      expect(mockCertificateIssue.mock.calls[0][0].validityStartDate).toEqual(undefined);
    });

    test('Custom start date should be honored', async () => {
      const customStartDate = new Date(stubFutureDate);
      customStartDate.setDate(customStartDate.getDate() - 1);

      jestDateMock.advanceTo(customStartDate.getTime() - 3_600_000);
      await issueInitialDHKeyCertificate({
        issuerCertificate: stubNodeCertificate,
        issuerPrivateKey: stubNodeKeyPair.privateKey,
        subjectPublicKey: stubSubjectKeyPair.publicKey,
        validityEndDate: stubFutureDate,
        validityStartDate: customStartDate,
      });

      expect(mockCertificateIssue.mock.calls[0][0].validityStartDate).toEqual(customStartDate);
    });

    test('End date should be honored', async () => {
      await issueInitialDHKeyCertificate({
        ...baseIssuanceOptions,
        validityEndDate: stubFutureDate,
      });

      expect(mockCertificateIssue.mock.calls[0][0].validityEndDate).toEqual(stubFutureDate);
    });

    test(`Certificate should not be valid for over ${MAX_VALIDITY_DAYS} days`, async () => {
      const startDate = new Date(stubFutureDate);
      startDate.setDate(stubFutureDate.getDate() - MAX_VALIDITY_DAYS);
      startDate.setMilliseconds(stubFutureDate.getMilliseconds() - 1);

      await expectPromiseToReject(
        issueInitialDHKeyCertificate({
          issuerCertificate: stubNodeCertificate,
          issuerPrivateKey: stubNodeKeyPair.privateKey,
          subjectPublicKey: stubSubjectKeyPair.publicKey,
          validityEndDate: stubFutureDate,
          validityStartDate: startDate,
        }),
        new DHCertificateError(`DH key may not be valid for more than ${MAX_VALIDITY_DAYS} days`),
      );
    });
  });

  test('Subject should not be marked as CA in Basic Constraints extension', async () => {
    await issueInitialDHKeyCertificate(baseIssuanceOptions);

    expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('isCA', false);
  });

  test('pathLenConstraint should be set to 0', async () => {
    await issueInitialDHKeyCertificate(baseIssuanceOptions);

    expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('pathLenConstraint', 0);
  });
});
