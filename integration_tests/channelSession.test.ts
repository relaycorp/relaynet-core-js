import { generateECDHKeyPair, generateRSAKeyPair } from '../src/lib/crypto_wrappers/keyGenerators';
import Certificate from '../src/lib/crypto_wrappers/x509/Certificate';
import { issueInitialDHKeyCertificate, issueNodeCertificate } from '../src/lib/nodes';

const TOMORROW = new Date();
TOMORROW.setDate(TOMORROW.getDate() + 1);

test('DH certificate can be issued, serialized and deserialized', async () => {
  const nodeKeyPair = await generateRSAKeyPair();
  const nodeCertificate = await issueNodeCertificate({
    isCA: true,
    issuerPrivateKey: nodeKeyPair.privateKey,
    serialNumber: 1,
    subjectPublicKey: nodeKeyPair.publicKey,
    validityEndDate: TOMORROW,
  });

  const dhKeyPair = await generateECDHKeyPair();
  const dhCertificate = await issueInitialDHKeyCertificate(
    dhKeyPair.publicKey,
    nodeKeyPair.privateKey,
    nodeCertificate,
    2,
    TOMORROW,
  );

  expect(dhCertificate.getCommonName()).toEqual(nodeCertificate.getCommonName());

  const dhCertificateSerialized = dhCertificate.serialize();
  const dhCertificateDeserialized = Certificate.deserialize(dhCertificateSerialized);
  expect(dhCertificateDeserialized.getCommonName()).toEqual(dhCertificate.getCommonName());
});
