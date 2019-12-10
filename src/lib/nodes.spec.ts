import * as pkijs from 'pkijs';

import { getMockContext, sha256Hex } from './_test_utils';
import { getPkijsCrypto } from './crypto_wrappers/_utils';
import { generateRSAKeyPair } from './crypto_wrappers/keyGenerators';
import Certificate from './crypto_wrappers/x509/Certificate';
import { issueNodeCertificate, NodeCertificateOptions } from './nodes';

const pkijsCrypto = getPkijsCrypto();

describe('issueNodeCertificate', () => {
  const stubCertificate: Certificate = new Certificate(new pkijs.Certificate());
  // tslint:disable-next-line:no-let
  let baseCertificateOptions: NodeCertificateOptions;
  // tslint:disable-next-line:no-let
  let stubSubjectKeyPair: CryptoKeyPair;

  beforeAll(async () => {
    stubSubjectKeyPair = await generateRSAKeyPair();
    baseCertificateOptions = {
      issuerPrivateKey: stubSubjectKeyPair.privateKey,
      serialNumber: 1,
      subjectPublicKey: stubSubjectKeyPair.publicKey,
      validityEndDate: new Date(),
    };
  });

  beforeEach(() => {
    jest.spyOn(Certificate, 'issue').mockResolvedValueOnce(Promise.resolve(stubCertificate));
  });

  test('Certificate should be a valid X.509 certificate', async () => {
    const certificate = await issueNodeCertificate(baseCertificateOptions);

    expect(certificate).toBe(stubCertificate);
  });

  test('Certificate should be issued with the original options', async () => {
    await issueNodeCertificate(baseCertificateOptions);

    expect(Certificate.issue).toBeCalledTimes(1);
    const certificateIssueCall = getMockContext(Certificate.issue).calls[0];
    expect(certificateIssueCall[0]).toMatchObject(baseCertificateOptions);
  });

  test('Certificate should have its private address as its Common Name (CN)', async () => {
    const { publicKey } = await generateRSAKeyPair();

    await issueNodeCertificate({
      ...baseCertificateOptions,
      subjectPublicKey: publicKey,
    });

    const certificateIssueCall = getMockContext(Certificate.issue).calls[0];
    const publicKeyDer = await pkijsCrypto.exportKey('spki', publicKey);
    expect(certificateIssueCall[0]).toHaveProperty('commonName', `0${sha256Hex(publicKeyDer)}`);
  });
});
