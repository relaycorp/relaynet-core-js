import { ObjectIdentifier, OctetString } from 'asn1js';

import { arrayBufferFrom, generateStubCert } from '../../_test_utils';
import { makeImplicitlyTaggedSequence } from '../../asn1';
import { SignedData } from '../../crypto/cms/signedData';
import { generateRSAKeyPair } from '../../crypto/keys';
import { Certificate } from '../../crypto/x509/Certificate';
import { STUB_OID_VALUE, StubSigner } from './_test_utils';

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

test('Signer certificate should be exposed', () => {
  const signer = new StubSigner(signerCertificate, signerPrivateKey);

  expect(signer.certificate).toEqual(signerCertificate);
});

describe('sign', () => {
  const OID = new ObjectIdentifier({ value: STUB_OID_VALUE });

  test('Plaintext should not be encapsulated', async () => {
    const signer = new StubSigner(signerCertificate, signerPrivateKey);

    const signedDataSerialized = await signer.sign(PLAINTEXT);

    const signedData = SignedData.deserialize(signedDataSerialized);
    expect(signedData.plaintext).toBeNull();
  });

  test('Certificate should be encapsulated', async () => {
    const signer = new StubSigner(signerCertificate, signerPrivateKey);

    const signedDataSerialized = await signer.sign(PLAINTEXT);

    const signedData = SignedData.deserialize(signedDataSerialized);
    expect(signedData.signerCertificate).not.toBeNull();
  });

  test('Signature should validate', async () => {
    const signer = new StubSigner(signerCertificate, signerPrivateKey);

    const signedDataSerialized = await signer.sign(PLAINTEXT);

    const signedData = SignedData.deserialize(signedDataSerialized);
    const expectedPlaintext = makeImplicitlyTaggedSequence(
      OID,
      new OctetString({ valueHex: PLAINTEXT }),
    ).toBER();
    await signedData.verify(expectedPlaintext);
  });
});
