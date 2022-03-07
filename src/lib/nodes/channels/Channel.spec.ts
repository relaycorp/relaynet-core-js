import { addDays, setMilliseconds } from 'date-fns';

import { arrayBufferFrom, CRYPTO_OIDS, reSerializeCertificate } from '../../_test_utils';
import { SessionEnvelopedData } from '../../crypto_wrappers/cms/envelopedData';
import {
  generateECDHKeyPair,
  generateRSAKeyPair,
  getPrivateAddressFromIdentityKey,
} from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { issueGatewayCertificate } from '../../pki';
import { StubPayload } from '../../ramf/_test_utils';
import { SessionKey } from '../../SessionKey';
import { NodeError } from '../errors';
import { Channel } from './Channel';

let peerPrivateAddress: string;
let peerPublicKey: CryptoKey;
let nodePrivateKey: CryptoKey;
let nodeCertificate: Certificate;
beforeAll(async () => {
  const tomorrow = setMilliseconds(addDays(new Date(), 1), 0);

  const peerKeyPair = await generateRSAKeyPair();
  peerPrivateAddress = await getPrivateAddressFromIdentityKey(peerKeyPair.publicKey);
  peerPublicKey = peerKeyPair.publicKey;
  const peerCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerPrivateKey: peerKeyPair.privateKey,
      subjectPublicKey: peerKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );

  const nodeKeyPair = await generateRSAKeyPair();
  nodePrivateKey = nodeKeyPair.privateKey;
  nodeCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: peerCertificate,
      issuerPrivateKey: peerKeyPair.privateKey,
      subjectPublicKey: nodeKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );
});

const KEY_STORES = new MockKeyStoreSet();
beforeEach(() => {
  KEY_STORES.clear();
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
    await KEY_STORES.publicKeyStore.saveSessionKey(peerSessionKey, peerPrivateAddress, new Date());
  });

  test('There should be a session key for the recipient', async () => {
    const unknownPeerPrivateAddress = `not-${peerPrivateAddress}`;
    const channel = new StubChannel(
      nodePrivateKey,
      nodeCertificate,
      unknownPeerPrivateAddress,
      peerPublicKey,
      KEY_STORES,
    );

    await expect(channel.wrapMessagePayload(stubPayload)).rejects.toThrowWithMessage(
      NodeError,
      `Could not find session key for peer ${unknownPeerPrivateAddress}`,
    );
  });

  test('Payload should be encrypted with the session key of the recipient', async () => {
    const channel = new StubChannel(
      nodePrivateKey,
      nodeCertificate,
      peerPrivateAddress,
      peerPublicKey,
      KEY_STORES,
    );

    const payloadSerialized = await channel.wrapMessagePayload(stubPayload);

    const payloadEnvelopedData = await SessionEnvelopedData.deserialize(payloadSerialized);
    expect(payloadEnvelopedData.getRecipientKeyId()).toEqual(peerSessionKey.keyId);
    await expect(payloadEnvelopedData.decrypt(peerSessionPrivateKey)).resolves.toEqual(
      stubPayload.serialize(),
    );
  });

  test('Passing the payload as an ArrayBuffer should be supported', async () => {
    const payloadPlaintext = stubPayload.serialize();
    const channel = new StubChannel(
      nodePrivateKey,
      nodeCertificate,
      peerPrivateAddress,
      peerPublicKey,
      KEY_STORES,
    );

    const payloadSerialized = await channel.wrapMessagePayload(stubPayload);

    const payloadEnvelopedData = await SessionEnvelopedData.deserialize(payloadSerialized);
    await expect(payloadEnvelopedData.decrypt(peerSessionPrivateKey)).resolves.toEqual(
      payloadPlaintext,
    );
  });

  test('The new ephemeral session key of the sender should be stored', async () => {
    const channel = new StubChannel(
      nodePrivateKey,
      nodeCertificate,
      peerPrivateAddress,
      peerPublicKey,
      KEY_STORES,
    );

    const payloadSerialized = await channel.wrapMessagePayload(stubPayload);

    const payloadEnvelopedData = (await SessionEnvelopedData.deserialize(
      payloadSerialized,
    )) as SessionEnvelopedData;
    const originatorSessionKey = await payloadEnvelopedData.getOriginatorKey();
    await expect(
      KEY_STORES.privateKeyStore.retrieveSessionKey(originatorSessionKey.keyId, peerPrivateAddress),
    ).resolves.toBeTruthy();
  });

  test('Encryption options should be honoured if set', async () => {
    const aesKeySize = 192;
    const channel = new StubChannel(
      nodePrivateKey,
      nodeCertificate,
      peerPrivateAddress,
      peerPublicKey,
      KEY_STORES,
      { encryption: { aesKeySize } },
    );

    const payloadSerialized = await channel.wrapMessagePayload(stubPayload);

    const payloadEnvelopedData = await SessionEnvelopedData.deserialize(payloadSerialized);
    const encryptedContentInfo = payloadEnvelopedData.pkijsEnvelopedData.encryptedContentInfo;
    expect(encryptedContentInfo.contentEncryptionAlgorithm.algorithmId).toEqual(
      CRYPTO_OIDS.AES_CBC_192,
    );
  });
});

class StubChannel extends Channel {}
