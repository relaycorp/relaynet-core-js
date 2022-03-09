import { addDays, setMilliseconds } from 'date-fns';

import { arrayBufferFrom, expectBuffersToEqual, reSerializeCertificate } from '../_test_utils';
import { SessionEnvelopedData } from '../crypto_wrappers/cms/envelopedData';
import {
  derSerializePublicKey,
  generateRSAKeyPair,
  getPrivateAddressFromIdentityKey,
} from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { MockKeyStoreSet } from '../keyStores/testMocks';
import { ParcelDeliverySigner, ParcelDeliveryVerifier } from '../messages/bindings/signatures';
import { issueGatewayCertificate } from '../pki';
import { StubMessage } from '../ramf/_test_utils';
import { SessionKey } from '../SessionKey';
import { SessionKeyPair } from '../SessionKeyPair';
import { StubNode } from './_test_utils';

let nodePrivateAddress: string;
let nodePrivateKey: CryptoKey;
let nodeCertificate: Certificate;
let nodeCertificateIssuer: Certificate;
let nodeCertificateIssuerPrivateAddress: string;
beforeAll(async () => {
  const tomorrow = setMilliseconds(addDays(new Date(), 1), 0);

  const issuerKeyPair = await generateRSAKeyPair();
  nodeCertificateIssuer = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );
  nodeCertificateIssuerPrivateAddress =
    await nodeCertificateIssuer.calculateSubjectPrivateAddress();

  const nodeKeyPair = await generateRSAKeyPair();
  nodePrivateKey = nodeKeyPair.privateKey;
  nodeCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: nodeCertificateIssuer,
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: nodeKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );
  nodePrivateAddress = await getPrivateAddressFromIdentityKey(nodeKeyPair.publicKey);
});

const KEY_STORES = new MockKeyStoreSet();
beforeEach(async () => {
  KEY_STORES.clear();
});

describe('getGSCSigner', () => {
  test('Nothing should be returned if certificate does not exist', async () => {
    const node = new StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});

    await expect(
      node.getGSCSigner(nodeCertificateIssuerPrivateAddress, ParcelDeliverySigner),
    ).resolves.toBeNull();
  });

  test('Signer should be of the type requested if certificate exists', async () => {
    const node = new StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
    await KEY_STORES.certificateStore.save(nodeCertificate, nodeCertificateIssuerPrivateAddress);

    const signer = await node.getGSCSigner(
      nodeCertificateIssuerPrivateAddress,
      ParcelDeliverySigner,
    );

    expect(signer).toBeInstanceOf(ParcelDeliverySigner);
  });

  test('Signer should receive the certificate and private key of the node', async () => {
    const node = new StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
    await KEY_STORES.certificateStore.save(nodeCertificate, nodeCertificateIssuerPrivateAddress);

    const signer = await node.getGSCSigner(
      nodeCertificateIssuerPrivateAddress,
      ParcelDeliverySigner,
    );

    const plaintext = arrayBufferFrom('hiya');
    const verifier = new ParcelDeliveryVerifier([nodeCertificateIssuer]);
    const signature = await signer!.sign(plaintext);
    await verifier.verify(signature, plaintext);
  });
});

describe('unwrapMessagePayload', () => {
  const PAYLOAD_PLAINTEXT_CONTENT = arrayBufferFrom('payload content');
  const RECIPIENT_ADDRESS = 'https://example.com';

  let peerCertificate: Certificate;
  beforeAll(async () => {
    const peerKeyPair = await generateRSAKeyPair();
    peerCertificate = await issueGatewayCertificate({
      issuerPrivateKey: peerKeyPair.privateKey,
      subjectPublicKey: peerKeyPair.publicKey,
      validityEndDate: addDays(new Date(), 1),
    });
  });

  let sessionKey: SessionKey;
  beforeEach(async () => {
    const sessionKeyPair = await SessionKeyPair.generate();
    sessionKey = sessionKeyPair.sessionKey;
    await KEY_STORES.privateKeyStore.saveUnboundSessionKey(
      sessionKeyPair.privateKey,
      sessionKeyPair.sessionKey.keyId,
    );
  });

  test('Payload plaintext should be returned', async () => {
    const { envelopedData } = await SessionEnvelopedData.encrypt(
      PAYLOAD_PLAINTEXT_CONTENT,
      sessionKey,
    );
    const message = new StubMessage(
      RECIPIENT_ADDRESS,
      peerCertificate,
      Buffer.from(envelopedData.serialize()),
    );
    const node = new StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});

    const payloadPlaintext = await node.unwrapMessagePayload(message);

    expectBuffersToEqual(payloadPlaintext.content, PAYLOAD_PLAINTEXT_CONTENT);
  });

  test('Originator session key should be stored', async () => {
    const { envelopedData, dhKeyId } = await SessionEnvelopedData.encrypt(
      PAYLOAD_PLAINTEXT_CONTENT,
      sessionKey,
    );
    const message = new StubMessage(
      RECIPIENT_ADDRESS,
      peerCertificate,
      Buffer.from(envelopedData.serialize()),
    );
    const node = new StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});

    await node.unwrapMessagePayload(message);

    const storedKey =
      KEY_STORES.publicKeyStore.sessionKeys[await peerCertificate.calculateSubjectPrivateAddress()];
    expect(storedKey.publicKeyCreationTime).toEqual(message.creationDate);
    expectBuffersToEqual(Buffer.from(dhKeyId), storedKey.publicKeyId);
    expectBuffersToEqual(
      await derSerializePublicKey((await envelopedData.getOriginatorKey()).publicKey),
      storedKey.publicKeyDer,
    );
  });
});
