import { generateECDHKeyPair, generateRSAKeyPair } from '../src/lib/crypto_wrappers/keyGenerators';
import { issueInitialDHKeyCertificate, issueNodeCertificate } from '../src/lib/nodes';

const TOMORROW = new Date();
TOMORROW.setDate(TOMORROW.getDate() + 1);

test('DH certificate can be issued', async () => {
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
});
