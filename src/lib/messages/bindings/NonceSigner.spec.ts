// tslint:disable:no-let

import { arrayBufferFrom, generateStubCert } from '../../_test_utils';
import { generateRSAKeyPair } from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { NONCE_SIGNATURE } from './DetachedSignature';
import { NonceSigner } from './NonceSigner';

describe('NonceSigner', () => {
  const nonce = arrayBufferFrom('The nonce');
  let keyPair: CryptoKeyPair;
  let certificate: Certificate;
  let caCertificate: Certificate;
  beforeAll(async () => {
    const caKeyPair = await generateRSAKeyPair();
    caCertificate = await generateStubCert({
      attributes: { isCA: true },
      issuerPrivateKey: caKeyPair.privateKey,
      subjectPublicKey: caKeyPair.publicKey,
    });

    keyPair = await generateRSAKeyPair();
    certificate = await generateStubCert({
      issuerCertificate: caCertificate,
      issuerPrivateKey: caKeyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
    });
  });

  test('Signature should be valid', async () => {
    const signer = new NonceSigner(certificate, keyPair.privateKey);

    const serialization = await signer.sign(nonce);

    await NONCE_SIGNATURE.verify(serialization, nonce, [caCertificate]);
  });

  test('Signer certificate should be exposed', () => {
    const signer = new NonceSigner(certificate, keyPair.privateKey);

    expect(signer.certificate).toEqual(certificate);
  });
});
