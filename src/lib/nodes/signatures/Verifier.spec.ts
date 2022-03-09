import { arrayBufferFrom, generateStubCert } from '../../_test_utils';
import CMSError from '../../crypto_wrappers/cms/CMSError';
import { generateRSAKeyPair } from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import CertificateError from '../../crypto_wrappers/x509/CertificateError';
import { StubSigner, StubVerifier } from './_test_utils';

let signerPrivateKey: CryptoKey;
let signerCertificate: Certificate;
let caCertificate: Certificate;
beforeAll(async () => {
  const caKeyPair = await generateRSAKeyPair();
  caCertificate = await generateStubCert({
    attributes: { isCA: true },
    issuerPrivateKey: caKeyPair.privateKey,
    subjectPublicKey: caKeyPair.publicKey,
  });

  const signerKeyPair = await generateRSAKeyPair();
  signerPrivateKey = signerKeyPair.privateKey;
  signerCertificate = await generateStubCert({
    issuerCertificate: caCertificate,
    issuerPrivateKey: caKeyPair.privateKey,
    subjectPublicKey: signerKeyPair.publicKey,
  });
});

const PLAINTEXT = arrayBufferFrom('the plaintext');

describe('verify', () => {
  test('Malformed signatures should be refused', async () => {
    const signedDataSerialized = arrayBufferFrom('not valid');
    const verifier = new StubVerifier([caCertificate]);

    await expect(verifier.verify(signedDataSerialized, PLAINTEXT)).rejects.toBeInstanceOf(CMSError);
  });

  test('Invalid signatures should be refused', async () => {
    const differentKeyPair = await generateRSAKeyPair();
    const illegitimateSigner = new StubSigner(signerCertificate, differentKeyPair.privateKey);
    const signedDataSerialized = await illegitimateSigner.sign(PLAINTEXT);
    const verifier = new StubVerifier([caCertificate]);

    await expect(verifier.verify(signedDataSerialized, PLAINTEXT)).rejects.toBeInstanceOf(CMSError);
  });

  test('Untrusted signers should be refused', async () => {
    const signer = new StubSigner(signerCertificate, signerPrivateKey);
    const signedDataSerialized = await signer.sign(PLAINTEXT);
    const verifier = new StubVerifier([]);

    await expect(verifier.verify(signedDataSerialized, PLAINTEXT)).rejects.toBeInstanceOf(
      CertificateError,
    );
  });

  test('Signer certificate should be output if trusted and signature is valid', async () => {
    const signer = new StubSigner(signerCertificate, signerPrivateKey);
    const signedDataSerialized = await signer.sign(PLAINTEXT);
    const verifier = new StubVerifier([caCertificate]);

    const actualSignerCertificate = await verifier.verify(signedDataSerialized, PLAINTEXT);

    await expect(actualSignerCertificate.isEqual(signerCertificate)).toBeTrue();
  });

  test('Signature should verify if issuer of signer is not a root CA', async () => {
    // PKI.js' SignedData.verify() can't be relied on to verify the signer, so we have to do our
    // own verification: https://github.com/relaycorp/relaynet-core-js/issues/178

    const caKeyPair = await generateRSAKeyPair();
    const rootCertificate = await generateStubCert({
      attributes: { isCA: true, pathLenConstraint: 1 },
      issuerPrivateKey: caKeyPair.privateKey,
      subjectPublicKey: caKeyPair.publicKey,
    });
    const intermediateKeyPair = await generateRSAKeyPair();
    const intermediateCertificate = await generateStubCert({
      attributes: { isCA: true, pathLenConstraint: 0 },
      issuerCertificate: rootCertificate,
      issuerPrivateKey: caKeyPair.privateKey,
      subjectPublicKey: intermediateKeyPair.publicKey,
    });
    const nonRootSignerKeyPair = await generateRSAKeyPair();
    const nonRootSignerCertificate = await generateStubCert({
      attributes: { isCA: true, pathLenConstraint: 0 },
      issuerCertificate: intermediateCertificate,
      issuerPrivateKey: intermediateKeyPair.privateKey,
      subjectPublicKey: nonRootSignerKeyPair.publicKey,
    });
    const signer = new StubSigner(nonRootSignerCertificate, nonRootSignerKeyPair.privateKey);
    const signedDataSerialized = await signer.sign(PLAINTEXT);

    const verifier = new StubVerifier([intermediateCertificate]);

    await verifier.verify(signedDataSerialized, PLAINTEXT);
  });
});
