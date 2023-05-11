import { addDays, setMilliseconds } from 'date-fns';

import { arrayBufferFrom, CRYPTO_OIDS, reSerializeCertificate } from '../../_test_utils';
import { SessionEnvelopedData } from '../../crypto/cms/envelopedData';
import { generateECDHKeyPair, generateRSAKeyPair } from '../../crypto/keys/generation';
import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { Recipient } from '../../messages/Recipient';
import { issueGatewayCertificate } from '../../pki/issuance';
import { StubPayload } from '../../ramf/_test_utils';
import { SessionKey } from '../../SessionKey';
import { NodeError } from '../errors';
import { getIdFromIdentityKey } from '../../crypto/keys/digest';
import { StubNode } from '../_test_utils';
import { Peer } from '../peer';
import { StubNodeChannel } from './_test_utils';
import { CertificationPath } from '../../pki/CertificationPath';

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

const PAYLOAD_PLAINTEXT_CONTENT = arrayBufferFrom('payload content');

describe('wrapMessagePayload', () => {
  const stubPayload = new StubPayload(PAYLOAD_PLAINTEXT_CONTENT);

  let peerSessionKey: SessionKey;
  let peerSessionPrivateKey: CryptoKey;
  beforeEach(async () => {
    const recipientSessionKeyPair = await generateECDHKeyPair();
    peerSessionPrivateKey = recipientSessionKeyPair.privateKey;
    peerSessionKey = {
      keyId: Buffer.from('key id'),
      publicKey: recipientSessionKeyPair.publicKey,
    };
    await KEY_STORES.publicKeyStore.saveSessionKey(peerSessionKey, peer.id, new Date());
  });

  test('There should be a session key for the recipient', async () => {
    const unknownPeerId = `not-${peer.id}`;
    const channel = new StubNodeChannel(
      node,
      { ...peer, id: unknownPeerId },
      deliveryAuthPath,
      KEY_STORES,
    );

    await expect(channel.wrapMessagePayload(stubPayload)).rejects.toThrowWithMessage(
      NodeError,
      `Could not find session key for peer ${unknownPeerId}`,
    );
  });

  test('Payload should be encrypted with the session key of the recipient', async () => {
    const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);

    const payloadSerialized = await channel.wrapMessagePayload(stubPayload);

    const payloadEnvelopedData = await SessionEnvelopedData.deserialize(payloadSerialized);
    expect(payloadEnvelopedData.getRecipientKeyId()).toEqual(peerSessionKey.keyId);
    await expect(payloadEnvelopedData.decrypt(peerSessionPrivateKey)).resolves.toEqual(
      stubPayload.serialize(),
    );
  });

  test('Passing the payload as an ArrayBuffer should be supported', async () => {
    const payloadPlaintext = stubPayload.serialize();
    const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);

    const payloadSerialized = await channel.wrapMessagePayload(stubPayload);

    const payloadEnvelopedData = await SessionEnvelopedData.deserialize(payloadSerialized);
    await expect(payloadEnvelopedData.decrypt(peerSessionPrivateKey)).resolves.toEqual(
      payloadPlaintext,
    );
  });

  test('The new ephemeral session key of the sender should be stored', async () => {
    const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);

    const payloadSerialized = await channel.wrapMessagePayload(stubPayload);

    const payloadEnvelopedData = (await SessionEnvelopedData.deserialize(
      payloadSerialized,
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

    const payloadSerialized = await channel.wrapMessagePayload(stubPayload);

    const payloadEnvelopedData = await SessionEnvelopedData.deserialize(payloadSerialized);
    const encryptedContentInfo = payloadEnvelopedData.pkijsEnvelopedData.encryptedContentInfo;
    expect(encryptedContentInfo.contentEncryptionAlgorithm.algorithmId).toEqual(
      CRYPTO_OIDS.AES_CBC_192,
    );
  });
});

describe('getOutboundRAMFRecipient', () => {
  test('Id should be output', () => {
    const channel = new StubNodeChannel(node, peer, deliveryAuthPath, KEY_STORES);

    expect(channel.getOutboundRAMFRecipient()).toEqual<Recipient>({ id: peer.id });
  });
});
