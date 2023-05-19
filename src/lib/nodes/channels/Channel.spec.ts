import { addDays, setMilliseconds, subSeconds } from 'date-fns';

import { arrayBufferFrom, CRYPTO_OIDS, reSerializeCertificate } from '../../_test_utils';
import { SessionEnvelopedData } from '../../crypto/cms/envelopedData';
import { generateRSAKeyPair } from '../../crypto/keys/generation';
import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { Recipient } from '../../messages/Recipient';
import { issueGatewayCertificate } from '../../pki/issuance';
import { StubMessage, StubPayload } from '../../ramf/_test_utils';
import { NodeError } from '../errors';
import { getIdFromIdentityKey } from '../../crypto/keys/digest';
import { StubNode } from '../_test_utils';
import { Peer } from '../peer';
import { StubNodeChannel } from './_test_utils';
import { CertificationPath } from '../../pki/CertificationPath';
import { SessionKeyPair } from '../../SessionKeyPair';
import { SignedData } from '../../crypto/cms/signedData';
import bufferToArray from 'buffer-to-arraybuffer';

const PAYLOAD_CONTENT = arrayBufferFrom('payload content');
const PAYLOAD = new StubPayload(PAYLOAD_CONTENT);

const KEY_STORES = new MockKeyStoreSet();
beforeEach(() => {
  KEY_STORES.clear();
});

let node: StubNode;
let peer: Peer<undefined>;
let deliveryAuthPath: CertificationPath;
beforeAll(async () => {
  const tomorrow = setMilliseconds(addDays(new Date(), 1), 0);

  const peerKeyPair = await generateRSAKeyPair();
  peer = {
    id: await getIdFromIdentityKey(peerKeyPair.publicKey),
    identityPublicKey: peerKeyPair.publicKey,
    internetAddress: undefined,
  };

  const peerCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerPrivateKey: peerKeyPair.privateKey,
      subjectPublicKey: peerKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );

  const nodeKeyPair = await generateRSAKeyPair();
  const nodeDeliveryAuth = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: peerCertificate,
      issuerPrivateKey: peerKeyPair.privateKey,
      subjectPublicKey: nodeKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );
  deliveryAuthPath = new CertificationPath(nodeDeliveryAuth, [peerCertificate]);

  node = new StubNode(
    await getIdFromIdentityKey(nodeKeyPair.publicKey),
    nodeKeyPair,
    KEY_STORES,
    {},
  );
});

describe('makeMessage', () => {
  let peerSessionKeyPair: SessionKeyPair;
  beforeEach(async () => {
    peerSessionKeyPair = await SessionKeyPair.generate();
    await KEY_STORES.publicKeyStore.saveSessionKey(
      peerSessionKeyPair.sessionKey,
      peer.id,
      new Date(),
    );

    await KEY_STORES.certificateStore.save(deliveryAuthPath, peer.id);
  });

  test('Recipient should be channel peer', async () => {
    const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);

    const messageSerialised = await channel.makeMessage(PAYLOAD, StubMessage);

    const { recipient } = await StubMessage.deserialize(messageSerialised);
    expect(recipient.id).toBe(peer.id);
    expect(recipient.internetAddress).toBe(peer.internetAddress);
  });

  test('Sender certificate should be delivery authorisation', async () => {
    const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);

    const messageSerialised = await channel.makeMessage(PAYLOAD, StubMessage);

    const { senderCertificate } = await StubMessage.deserialize(messageSerialised);
    expect(senderCertificate.isEqual(deliveryAuthPath.leafCertificate)).toBeTrue();
  });

  test('Sender certificate CAs should be delivery authorisation CAs', async () => {
    const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);

    const messageSerialised = await channel.makeMessage(PAYLOAD, StubMessage);

    const { senderCaCertificateChain } = await StubMessage.deserialize(messageSerialised);
    expect(senderCaCertificateChain).toHaveLength(1);
    expect(
      senderCaCertificateChain[0].isEqual(deliveryAuthPath.certificateAuthorities[0]),
    ).toBeTrue();
  });

  describe('Payload', () => {
    test('There should be a session key for the recipient', async () => {
      const unknownPeerId = `not-${peer.id}`;
      const channel = new StubNodeChannel(
        node,
        { ...peer, id: unknownPeerId },
        deliveryAuthPath,
        KEY_STORES,
      );

      await expect(channel.makeMessage(PAYLOAD, StubMessage)).rejects.toThrowWithMessage(
        NodeError,
        `Could not find session key for peer ${unknownPeerId}`,
      );
    });

    test('Payload should be encrypted with the session key of the recipient', async () => {
      const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);

      const messageSerialised = await channel.makeMessage(PAYLOAD, StubMessage);

      const message = await StubMessage.deserialize(messageSerialised);
      const payloadEnvelopedData = await SessionEnvelopedData.deserialize(
        message.payloadSerialized,
      );
      expect(payloadEnvelopedData.getRecipientKeyId()).toEqual(peerSessionKeyPair.sessionKey.keyId);
      await expect(payloadEnvelopedData.decrypt(peerSessionKeyPair.privateKey)).resolves.toEqual(
        PAYLOAD.serialize(),
      );
    });

    test('Passing the payload as an ArrayBuffer should be supported', async () => {
      const payloadPlaintext = PAYLOAD.serialize();
      const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);

      const messageSerialized = await channel.makeMessage(PAYLOAD_CONTENT, StubMessage);

      const message = await StubMessage.deserialize(messageSerialized);
      const payloadEnvelopedData = await SessionEnvelopedData.deserialize(
        message.payloadSerialized,
      );
      await expect(payloadEnvelopedData.decrypt(peerSessionKeyPair.privateKey)).resolves.toEqual(
        payloadPlaintext,
      );
    });

    test('The new ephemeral session key of the sender should be stored', async () => {
      const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);

      const messageSerialized = await channel.makeMessage(PAYLOAD, StubMessage);

      const message = await StubMessage.deserialize(messageSerialized);
      const payloadEnvelopedData = (await SessionEnvelopedData.deserialize(
        message.payloadSerialized,
      )) as SessionEnvelopedData;
      const originatorSessionKey = await payloadEnvelopedData.getOriginatorKey();
      await expect(
        KEY_STORES.privateKeyStore.retrieveSessionKey(originatorSessionKey.keyId, node.id, peer.id),
      ).resolves.toBeTruthy();
    });

    test('Encryption options should be honoured if set', async () => {
      const aesKeySize = 192;
      const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES, {
        encryption: { aesKeySize },
      });

      const messageSerialized = await channel.makeMessage(PAYLOAD, StubMessage);

      const message = await StubMessage.deserialize(messageSerialized);
      const payloadEnvelopedData = await SessionEnvelopedData.deserialize(
        message.payloadSerialized,
      );
      const encryptedContentInfo = payloadEnvelopedData.pkijsEnvelopedData.encryptedContentInfo;
      expect(encryptedContentInfo.contentEncryptionAlgorithm.algorithmId).toEqual(
        CRYPTO_OIDS.AES_CBC_192,
      );
    });
  });

  describe('Creation date', () => {
    test('Creation date should default to now', async () => {
      const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);
      const dateBeforeMessage = setMilliseconds(new Date(), 0);

      const messageSerialized = await channel.makeMessage(PAYLOAD, StubMessage);

      const { creationDate } = await StubMessage.deserialize(messageSerialized);
      expect(creationDate).toBeAfterOrEqualTo(dateBeforeMessage);
      expect(creationDate).toBeBeforeOrEqualTo(new Date());
    });

    test('Creation date should be honoured if set', async () => {
      const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);
      const creationDate = setMilliseconds(subSeconds(new Date(), 15), 0);

      const messageSerialized = await channel.makeMessage(PAYLOAD, StubMessage, { creationDate });

      const message = await StubMessage.deserialize(messageSerialized);
      expect(message.creationDate).toStrictEqual(creationDate);
    });
  });

  describe('TTL', () => {
    test('TTL should default to 5 minutes', async () => {
      const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);

      const messageSerialized = await channel.makeMessage(PAYLOAD, StubMessage);

      const { ttl } = await StubMessage.deserialize(messageSerialized);
      expect(ttl).toStrictEqual(300);
    });

    test('TTL should be honoured if set', async () => {
      const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);
      const ttl = 60;

      const messageSerialized = await channel.makeMessage(PAYLOAD, StubMessage, { ttl });

      const message = await StubMessage.deserialize(messageSerialized);
      expect(message.ttl).toBe(ttl);
    });
  });

  test('Signature options should be honoured if set', async () => {
    const hashingAlgorithmName = 'SHA-384';
    const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES, {
      signature: { hashingAlgorithmName },
    });

    const messageSerialised = await channel.makeMessage(PAYLOAD, StubMessage);

    const signedDataSerialised = bufferToArray(Buffer.from(messageSerialised).subarray(7));
    const signedData = await SignedData.deserialize(signedDataSerialised);
    const [signerInfo] = signedData.pkijsSignedData.signerInfos;
    expect(signerInfo.digestAlgorithm.algorithmId).toBe(CRYPTO_OIDS.SHA_384);
  });
});

describe('getOutboundRAMFRecipient', () => {
  test('Id should be output', () => {
    const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);

    expect(channel.getOutboundRAMFRecipient()).toEqual<Recipient>({ id: peer.id });
  });
});
