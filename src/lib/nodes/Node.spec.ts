import { arrayBufferFrom, generateStubCert } from '../_test_utils';
import { generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { ParcelDeliverySigner, ParcelDeliveryVerifier } from '../messages/bindings/signatures';
import { Node } from './Node';

let nodePrivateKey: CryptoKey;
let nodeCertificate: Certificate;
beforeAll(async () => {
  const nodeKeyPair = await generateRSAKeyPair();
  nodePrivateKey = nodeKeyPair.privateKey;
  nodeCertificate = await generateStubCert({
    attributes: { isCA: true },
    issuerPrivateKey: nodeKeyPair.privateKey,
    subjectPublicKey: nodeKeyPair.publicKey,
  });
});

describe('getSigner', () => {
  test('Signer should be of the type requested', () => {
    const node = new StubNode(nodeCertificate, nodePrivateKey);

    const signer = node.getSigner(ParcelDeliverySigner);

    expect(signer).toBeInstanceOf(ParcelDeliverySigner);
  });

  test('Signer should receive the certificate and private key of the node', async () => {
    const node = new StubNode(nodeCertificate, nodePrivateKey);

    const signer = node.getSigner(ParcelDeliverySigner);

    const plaintext = arrayBufferFrom('hiya');
    const verifier = new ParcelDeliveryVerifier([nodeCertificate]);
    const signature = await signer.sign(plaintext);
    await verifier.verify(signature, plaintext);
  });
});

class StubNode extends Node {
  constructor(certificate: Certificate, privateKey: CryptoKey) {
    super(certificate, privateKey);
  }
}
