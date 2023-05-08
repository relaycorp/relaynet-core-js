import * as pkijs from 'pkijs';

import { generateStubCert } from '../_test_utils';
import { generateRSAKeyPair, getPublicKeyDigestHex } from '../crypto/keys';
import { BasicCertificateIssuanceOptions } from '../crypto/x509/BasicCertificateIssuanceOptions';
import { Certificate } from '../crypto/x509/Certificate';
import {
  DeliveryAuthorizationIssuanceOptions,
  GatewayCertificateIssuanceOptions,
  issueDeliveryAuthorization,
  issueEndpointCertificate,
  issueGatewayCertificate,
} from './issuance';

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

  test('Certificate should have its id as its Common Name (CN)', async () => {
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

  test('Certificate should have its id as its Common Name (CN)', async () => {
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

  test('Certificate should have its id as its Common Name (CN)', async () => {
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
