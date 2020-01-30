/* tslint:disable:no-let */

import { expectPromiseToReject, generateStubCert } from '../../_test_utils';
import { generateRSAKeyPair } from '../keys';
import Certificate from './Certificate';
import { UntrustedCertificateError, validateCertificateTrust } from './chainValidation';

describe('validateCertificateTrust', () => {
  let stubTrustedCaPrivateKey: CryptoKey;
  let stubTrustedCa: Certificate;

  beforeAll(async () => {
    const trustedCaKeyPair = await generateRSAKeyPair();
    stubTrustedCaPrivateKey = trustedCaKeyPair.privateKey;
    stubTrustedCa = reSerializeCertificate(
      await generateStubCert({
        attributes: { isCA: true },
        issuerPrivateKey: trustedCaKeyPair.privateKey,
        subjectPublicKey: trustedCaKeyPair.publicKey,
      }),
    );
  });

  test('Cert issued by trusted cert should be trusted', async () => {
    const cert = await generateStubCert({
      issuerCertificate: stubTrustedCa,
      issuerPrivateKey: stubTrustedCaPrivateKey,
    });

    await expect(
      validateCertificateTrust(reSerializeCertificate(cert), [], [stubTrustedCa]),
    ).toResolve();
  });

  test('Cert not issued by trusted cert should not be trusted', async () => {
    const cert = await generateStubCert();

    await expectPromiseToReject(
      validateCertificateTrust(cert, [], [stubTrustedCa]),
      new UntrustedCertificateError('No valid certificate paths found'),
    );
  });

  test('Cert issued by intermediate CA should be trusted', async () => {
    const intermediateCaKeyPair = await generateRSAKeyPair();
    const intermediateCaCert = await generateStubCert({
      attributes: { isCA: true },
      issuerCertificate: stubTrustedCa,
      issuerPrivateKey: stubTrustedCaPrivateKey,
      subjectPublicKey: intermediateCaKeyPair.publicKey,
    });

    const cert = await generateStubCert({
      issuerCertificate: intermediateCaCert,
      issuerPrivateKey: intermediateCaKeyPair.privateKey,
    });

    await expect(
      validateCertificateTrust(
        reSerializeCertificate(cert),
        [reSerializeCertificate(intermediateCaCert)],
        [stubTrustedCa],
      ),
    ).toResolve();
  });

  test('Cert issued by untrusted intermediate CA should not be trusted', async () => {
    const untrustedIntermediateCaKeyPair = await generateRSAKeyPair();
    const untrustedIntermediateCaCert = await generateStubCert({
      attributes: { isCA: true },
      issuerPrivateKey: untrustedIntermediateCaKeyPair.privateKey,
      subjectPublicKey: untrustedIntermediateCaKeyPair.publicKey,
    });

    const cert = await generateStubCert({
      issuerCertificate: untrustedIntermediateCaCert,
      issuerPrivateKey: untrustedIntermediateCaKeyPair.privateKey,
    });

    await expectPromiseToReject(
      validateCertificateTrust(
        reSerializeCertificate(cert),
        [reSerializeCertificate(untrustedIntermediateCaCert)],
        [stubTrustedCa],
      ),
      new UntrustedCertificateError('No valid certificate paths found'),
    );
  });

  test('Including trusted intermediate CA should not make certificate trusted', async () => {
    const intermediateCaKeyPair = await generateRSAKeyPair();
    const trustedIntermediateCaCert = await generateStubCert({
      attributes: { isCA: true },
      issuerPrivateKey: intermediateCaKeyPair.privateKey,
      subjectPublicKey: intermediateCaKeyPair.publicKey,
    });

    const cert = await generateStubCert();

    await expectPromiseToReject(
      validateCertificateTrust(cert, [trustedIntermediateCaCert], [stubTrustedCa]),
      new UntrustedCertificateError('No valid certificate paths found'),
    );
  });
});

function reSerializeCertificate(cert: Certificate): Certificate {
  // TODO: Raise bug in PKI.js project
  // PKI.js sometimes tries to use attributes that are only set *after* the certificate has been
  // deserialized, so you'd get a TypeError if you use a certificate you just created in memory.
  // For example, `extension.parsedValue` would be `undefined` in
  // https://github.com/PeculiarVentures/PKI.js/blob/9a39551aa9f1445406f96680318014c8d714e8e3/src/CertificateChainValidationEngine.js#L155
  return Certificate.deserialize(cert.serialize());
}
