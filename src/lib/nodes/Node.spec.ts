import { addDays, setMilliseconds, subDays } from 'date-fns';

import { arrayBufferFrom, expectArrayBuffersToEqual, reSerializeCertificate } from '../_test_utils';
import { SessionEnvelopedData } from '../crypto/cms/envelopedData';
import { generateRSAKeyPair } from '../crypto/keys/generation';
import { Certificate } from '../crypto/x509/Certificate';
import { MockKeyStoreSet } from '../keyStores/testMocks';
import { ParcelDeliverySigner, ParcelDeliveryVerifier } from '../messages/bindings/signatures';
import { CertificationPath } from '../pki/CertificationPath';
import { issueGatewayCertificate } from '../pki/issuance';
import { StubMessage } from '../ramf/_test_utils';
import { StubNode } from './_test_utils';
import { InvalidMessageError } from '../messages/InvalidMessageError';
import { derSerializePublicKey } from '../crypto/keys/serialisation';
import { getIdFromIdentityKey } from '../crypto/keys/digest';

let nodeId: string;
let nodeKeyPair: CryptoKeyPair;
let nodeCertificate: Certificate;
let nodeCertificateIssuer: Certificate;
let nodeCertificateIssuerId: string;
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
  nodeCertificateIssuerId = await nodeCertificateIssuer.calculateSubjectId();

  nodeKeyPair = await generateRSAKeyPair();
  nodeCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: nodeCertificateIssuer,
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: nodeKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );
  nodeId = await getIdFromIdentityKey(nodeKeyPair.publicKey);
});

let peerId: string;
let peerCertificate: Certificate;
beforeAll(async () => {
  const peerKeyPair = await generateRSAKeyPair();
  peerId = await getIdFromIdentityKey(peerKeyPair.publicKey);
  peerCertificate = await issueGatewayCertificate({
    issuerCertificate: nodeCertificate,
    issuerPrivateKey: nodeKeyPair.privateKey,
    subjectPublicKey: peerKeyPair.publicKey,
    validityEndDate: addDays(new Date(), 1),
  });
});

const KEY_STORES = new MockKeyStoreSet();
beforeEach(async () => {
  KEY_STORES.clear();
});

describe('getGSCSigner', () => {
  test('Nothing should be returned if certificate does not exist', async () => {
    const node = new StubNode(nodeId, nodeKeyPair, KEY_STORES, {});

    await expect(
      node.getGSCSigner(nodeCertificateIssuerId, ParcelDeliverySigner),
    ).resolves.toBeNull();
  });

  test('Signer should be of the type requested if certificate exists', async () => {
    const node = new StubNode(nodeId, nodeKeyPair, KEY_STORES, {});
    await KEY_STORES.certificateStore.save(
      new CertificationPath(nodeCertificate, []),
      nodeCertificateIssuerId,
    );

    const signer = await node.getGSCSigner(nodeCertificateIssuerId, ParcelDeliverySigner);

    expect(signer).toBeInstanceOf(ParcelDeliverySigner);
  });

  test('Signer should receive the certificate and private key of the node', async () => {
    const node = new StubNode(nodeId, nodeKeyPair, KEY_STORES, {});
    await KEY_STORES.certificateStore.save(
      new CertificationPath(nodeCertificate, []),
      nodeCertificateIssuerId,
    );

    const signer = await node.getGSCSigner(nodeCertificateIssuerId, ParcelDeliverySigner);

    const plaintext = arrayBufferFrom('hiya');
    const verifier = new ParcelDeliveryVerifier([nodeCertificateIssuer]);
    const signature = await signer!.sign(plaintext);
    await verifier.verify(signature, plaintext);
  });
});

describe('generateSessionKey', () => {
  test('Key should not be bound to any peer by default', async () => {
    const node = new StubNode(nodeId, nodeKeyPair, KEY_STORES, {});

    const sessionKey = await node.generateSessionKey();

    await expect(
      derSerializePublicKey(
        await KEY_STORES.privateKeyStore.retrieveUnboundSessionKey(sessionKey.keyId, node.id),
      ),
    ).resolves.toEqual(await derSerializePublicKey(sessionKey.publicKey));
  });

  test('Key should be bound to a peer if explicitly set', async () => {
    const node = new StubNode(nodeId, nodeKeyPair, KEY_STORES, {});

    const sessionKey = await node.generateSessionKey(peerId);

    await expect(
      derSerializePublicKey(
        await KEY_STORES.privateKeyStore.retrieveSessionKey(sessionKey.keyId, node.id, peerId),
      ),
    ).resolves.toEqual(await derSerializePublicKey(sessionKey.publicKey));
  });
});

describe('validateMessage', () => {
  test('Invalid message should be refused', async () => {
    const node = new StubNode(nodeId, nodeKeyPair, KEY_STORES, {});
    const expiredMessage = new StubMessage({ id: nodeId }, peerCertificate, Buffer.from([]), {
      creationDate: subDays(new Date(), 1),
      ttl: 1,
    });

    await expect(node.validateMessage(expiredMessage)).rejects.toThrowWithMessage(
      InvalidMessageError,
      /expired/,
    );
  });

  test('Valid message with untrusted sender should be refused', async () => {
    const node = new StubNode(nodeId, nodeKeyPair, KEY_STORES, {});
    const message = new StubMessage({ id: nodeId }, peerCertificate, Buffer.from([]));

    await expect(node.validateMessage(message, [])).rejects.toThrowWithMessage(
      InvalidMessageError,
      /authorized/,
    );
  });

  test('Valid message with trusted sender should be allowed', async () => {
    const node = new StubNode(nodeId, nodeKeyPair, KEY_STORES, {});
    const message = new StubMessage({ id: nodeId }, peerCertificate, Buffer.from([]), {
      senderCaCertificateChain: [peerCertificate],
    });

    await expect(node.validateMessage(message, [nodeCertificate])).toResolve();
  });

  test('Message recipient should match node id', async () => {
    const node = new StubNode(nodeId, nodeKeyPair, KEY_STORES, {});
    const message = new StubMessage({ id: `not${nodeId}` }, peerCertificate, Buffer.from([]));

    await expect(node.validateMessage(message)).rejects.toThrowWithMessage(
      InvalidMessageError,
      `Message is bound for another node (${message.recipient.id})`,
    );
  });

  test('Valid message should be allowed', async () => {
    const node = new StubNode(nodeId, nodeKeyPair, KEY_STORES, {});
    const message = new StubMessage({ id: nodeId }, peerCertificate, Buffer.from([]));

    await expect(node.validateMessage(message)).toResolve();
  });
});

describe('unwrapMessagePayload', () => {
  const PAYLOAD_PLAINTEXT_CONTENT = arrayBufferFrom('payload content');

  test('Payload plaintext should be returned', async () => {
    const node = new StubNode(peerId, nodeKeyPair, KEY_STORES, {});
    const sessionKey = await node.generateSessionKey(peerId);
    const { envelopedData } = await SessionEnvelopedData.encrypt(
      PAYLOAD_PLAINTEXT_CONTENT,
      sessionKey,
    );
    const message = new StubMessage(
      { id: peerId },
      peerCertificate,
      Buffer.from(envelopedData.serialize()),
    );

    const payloadPlaintext = await node.unwrapMessagePayload(message);

    expectArrayBuffersToEqual(payloadPlaintext.content, PAYLOAD_PLAINTEXT_CONTENT);
  });

  test('Originator session key should be stored', async () => {
    const node = new StubNode(peerId, nodeKeyPair, KEY_STORES, {});
    const sessionKey = await node.generateSessionKey(peerId);
    const { envelopedData, dhKeyId } = await SessionEnvelopedData.encrypt(
      PAYLOAD_PLAINTEXT_CONTENT,
      sessionKey,
    );
    const message = new StubMessage(
      { id: peerId },
      peerCertificate,
      Buffer.from(envelopedData.serialize()),
    );

    await node.unwrapMessagePayload(message);

    const storedKey =
      KEY_STORES.publicKeyStore.sessionKeys[await peerCertificate.calculateSubjectId()];
    expect(storedKey.publicKeyCreationTime).toEqual(message.creationDate);
    expect(storedKey.publicKeyId).toEqual(Buffer.from(dhKeyId));
    expect(storedKey.publicKeyDer).toEqual(
      await derSerializePublicKey((await envelopedData.getOriginatorKey()).publicKey),
    );
  });
});
