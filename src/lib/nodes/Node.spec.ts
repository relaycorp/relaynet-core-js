import { addDays, setMilliseconds } from 'date-fns';

import { arrayBufferFrom, expectBuffersToEqual, reSerializeCertificate } from '../_test_utils';
import { SessionEnvelopedData } from '../crypto_wrappers/cms/envelopedData';
import { derSerializePublicKey, generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { KeyStoreSet } from '../keyStores/KeyStoreSet';
import {
  MockCertificateStore,
  MockPrivateKeyStore,
  MockPublicKeyStore,
} from '../keyStores/testMocks';
import { ParcelDeliverySigner, ParcelDeliveryVerifier } from '../messages/bindings/signatures';
import { issueGatewayCertificate } from '../pki';
import { StubMessage } from '../ramf/_test_utils';
import { SessionKey } from '../SessionKey';
import { SessionKeyPair } from '../SessionKeyPair';
import { StubNode } from './_test_utils';

const TOMORROW = setMilliseconds(addDays(new Date(), 1), 0);

let nodePrivateKey: CryptoKey;
let nodeCertificate: Certificate;
let nodeCertificateIssuer: Certificate;
let peerCertificate: Certificate;
beforeAll(async () => {
  const issuerKeyPair = await generateRSAKeyPair();
  nodeCertificateIssuer = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
      validityEndDate: TOMORROW,
    }),
  );

  const nodeKeyPair = await generateRSAKeyPair();
  nodePrivateKey = nodeKeyPair.privateKey;
  nodeCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: nodeCertificateIssuer,
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: nodeKeyPair.publicKey,
      validityEndDate: TOMORROW,
    }),
  );

  const peerKeyPair = await generateRSAKeyPair();
  peerCertificate = await issueGatewayCertificate({
    issuerPrivateKey: peerKeyPair.privateKey,
    subjectPublicKey: peerKeyPair.publicKey,
    validityEndDate: TOMORROW,
  });
});

const PRIVATE_KEY_STORE = new MockPrivateKeyStore();
const PUBLIC_KEY_STORE = new MockPublicKeyStore();
const CERTIFICATE_STORE = new MockCertificateStore();
const KEY_STORES: KeyStoreSet = {
  certificateStore: CERTIFICATE_STORE,
  privateKeyStore: PRIVATE_KEY_STORE,
  publicKeyStore: PUBLIC_KEY_STORE,
};
beforeEach(async () => {
  PRIVATE_KEY_STORE.clear();
  PUBLIC_KEY_STORE.clear();
  CERTIFICATE_STORE.clear();
});

const PAYLOAD_PLAINTEXT_CONTENT = arrayBufferFrom('payload content');

describe('getGSCSigner', () => {
  let nodeCertificateIssuerPrivateAddress: string;
  beforeAll(async () => {
    nodeCertificateIssuerPrivateAddress =
      await nodeCertificateIssuer.calculateSubjectPrivateAddress();
  });

  beforeEach(async () => {
    await CERTIFICATE_STORE.save(nodeCertificate, nodeCertificateIssuerPrivateAddress);
  });

  test('Nothing should be returned if certificate does not exist', async () => {
    const node = new StubNode(nodePrivateKey, KEY_STORES, {});
    CERTIFICATE_STORE.clear();

    await expect(
      node.getGSCSigner(nodeCertificateIssuerPrivateAddress, ParcelDeliverySigner),
    ).resolves.toBeNull();
  });

  test('Signer should be of the type requested if certificate exists', async () => {
    const node = new StubNode(nodePrivateKey, KEY_STORES, {});

    const signer = await node.getGSCSigner(
      nodeCertificateIssuerPrivateAddress,
      ParcelDeliverySigner,
    );

    expect(signer).toBeInstanceOf(ParcelDeliverySigner);
  });

  test('Signer should receive the certificate and private key of the node', async () => {
    const node = new StubNode(nodePrivateKey, KEY_STORES, {});

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
  const RECIPIENT_ADDRESS = 'https://example.com';

  let sessionKey: SessionKey;
  beforeEach(async () => {
    const sessionKeyPair = await SessionKeyPair.generate();
    sessionKey = sessionKeyPair.sessionKey;
    await PRIVATE_KEY_STORE.saveUnboundSessionKey(
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
    const node = new StubNode(nodePrivateKey, KEY_STORES, {});

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
    const node = new StubNode(nodePrivateKey, KEY_STORES, {});

    await node.unwrapMessagePayload(message);

    const storedKey =
      PUBLIC_KEY_STORE.sessionKeys[await peerCertificate.calculateSubjectPrivateAddress()];
    expect(storedKey.publicKeyCreationTime).toEqual(message.creationDate);
    expectBuffersToEqual(Buffer.from(dhKeyId), storedKey.publicKeyId);
    expectBuffersToEqual(
      await derSerializePublicKey((await envelopedData.getOriginatorKey()).publicKey),
      storedKey.publicKeyDer,
    );
  });
});
