import { arrayBufferFrom, CRYPTO_OIDS, expectBuffersToEqual } from '../../_test_utils';
import { SessionEnvelopedData } from '../../crypto_wrappers/cms/envelopedData';
import {
  derSerializePublicKey,
  generateECDHKeyPair,
  generateRSAKeyPair,
} from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { MockPrivateKeyStore, MockPublicKeyStore } from '../../keyStores/testMocks';
import { issueGatewayCertificate } from '../../pki';
import { StubMessage, StubPayload } from '../../ramf/_test_utils';
import { SessionKey } from '../../SessionKey';
import { SessionKeyPair } from '../../SessionKeyPair';
import { BaseNodeManager } from './BaseNodeManager';
import { NodeError } from '../errors';

const TOMORROW = new Date();
TOMORROW.setDate(TOMORROW.getDate() + 1);
TOMORROW.setMilliseconds(0);

let senderCertificate: Certificate;
beforeAll(async () => {
  const senderKeyPair = await generateRSAKeyPair();
  senderCertificate = await issueGatewayCertificate({
    issuerPrivateKey: senderKeyPair.privateKey,
    subjectPublicKey: senderKeyPair.publicKey,
    validityEndDate: TOMORROW,
  });
});

let recipientPrivateKey: CryptoKey;
let recipientCertificate: Certificate;
beforeAll(async () => {
  const recipientKeyPair = await generateRSAKeyPair();
  recipientPrivateKey = recipientKeyPair.privateKey;

  recipientCertificate = await issueGatewayCertificate({
    issuerPrivateKey: recipientKeyPair.privateKey,
    subjectPublicKey: recipientKeyPair.publicKey,
    validityEndDate: TOMORROW,
  });
});

const privateKeyStore = new MockPrivateKeyStore();
const publicKeyStore = new MockPublicKeyStore();
beforeEach(async () => {
  privateKeyStore.clear();
  publicKeyStore.clear();

  await privateKeyStore.saveIdentityKey(recipientPrivateKey);
});

const PAYLOAD_PLAINTEXT_CONTENT = arrayBufferFrom('payload content');

describe('generateSessionKey', () => {
  test('Key should not be bound to any peer by default', async () => {
    const node = new StubNodeManager(privateKeyStore, publicKeyStore);

    const sessionKey = await node.generateSessionKey();

    await expect(
      derSerializePublicKey(await privateKeyStore.retrieveUnboundSessionKey(sessionKey.keyId)),
    ).resolves.toEqual(await derSerializePublicKey(sessionKey.publicKey));
  });

  test('Key should be bound to a peer if explicitly set', async () => {
    const node = new StubNodeManager(privateKeyStore, publicKeyStore);
    const peerPrivateAddress = '0deadbeef';

    const sessionKey = await node.generateSessionKey(peerPrivateAddress);

    await expect(
      derSerializePublicKey(
        await privateKeyStore.retrieveSessionKey(sessionKey.keyId, peerPrivateAddress),
      ),
    ).resolves.toEqual(await derSerializePublicKey(sessionKey.publicKey));
  });
});

describe('wrapMessagePayload', () => {
  const stubPayload = new StubPayload(PAYLOAD_PLAINTEXT_CONTENT);

  let recipientSessionKey: SessionKey;
  let recipientSessionPrivateKey: CryptoKey;
  beforeEach(async () => {
    const recipientSessionKeyPair = await generateECDHKeyPair();
    recipientSessionPrivateKey = recipientSessionKeyPair.privateKey;
    recipientSessionKey = {
      keyId: Buffer.from('key id'),
      publicKey: recipientSessionKeyPair.publicKey,
    };
    await publicKeyStore.saveSessionKey(
      recipientSessionKey,
      await recipientCertificate.calculateSubjectPrivateAddress(),
      new Date(),
    );
  });

  test('There should be a session key for the recipient', async () => {
    const node = new StubNodeManager(privateKeyStore, publicKeyStore);
    const peerPrivateAddress = 'non-existing';

    await expect(
      node.wrapMessagePayload(stubPayload, peerPrivateAddress),
    ).rejects.toThrowWithMessage(
      NodeError,
      `Could not find session key for peer ${peerPrivateAddress}`,
    );
  });

  test('Payload should be encrypted with the session key of the recipient', async () => {
    const node = new StubNodeManager(privateKeyStore, publicKeyStore);

    const payloadSerialized = await node.wrapMessagePayload(
      stubPayload,
      await recipientCertificate.calculateSubjectPrivateAddress(),
    );

    const payloadEnvelopedData = await SessionEnvelopedData.deserialize(payloadSerialized);
    expect(payloadEnvelopedData.getRecipientKeyId()).toEqual(recipientSessionKey.keyId);
    await expect(payloadEnvelopedData.decrypt(recipientSessionPrivateKey)).resolves.toEqual(
      stubPayload.serialize(),
    );
  });

  test('Passing the payload as an ArrayBuffer should be supported', async () => {
    const node = new StubNodeManager(privateKeyStore, publicKeyStore);
    const payloadPlaintext = stubPayload.serialize();

    const payloadSerialized = await node.wrapMessagePayload(
      payloadPlaintext,
      await recipientCertificate.calculateSubjectPrivateAddress(),
    );

    const payloadEnvelopedData = await SessionEnvelopedData.deserialize(payloadSerialized);
    await expect(payloadEnvelopedData.decrypt(recipientSessionPrivateKey)).resolves.toEqual(
      payloadPlaintext,
    );
  });

  test('The new ephemeral session key of the sender should be stored', async () => {
    const node = new StubNodeManager(privateKeyStore, publicKeyStore);

    const payloadSerialized = await node.wrapMessagePayload(
      stubPayload,
      await recipientCertificate.calculateSubjectPrivateAddress(),
    );

    const payloadEnvelopedData = (await SessionEnvelopedData.deserialize(
      payloadSerialized,
    )) as SessionEnvelopedData;
    const originatorSessionKey = await payloadEnvelopedData.getOriginatorKey();
    await expect(
      privateKeyStore.retrieveSessionKey(
        originatorSessionKey.keyId,
        await recipientCertificate.calculateSubjectPrivateAddress(),
      ),
    ).resolves.toBeTruthy();
  });

  test('Encryption options should be honoured if set', async () => {
    const aesKeySize = 192;
    const node = new StubNodeManager(privateKeyStore, publicKeyStore, {
      encryption: { aesKeySize },
    });

    const payloadSerialized = await node.wrapMessagePayload(
      stubPayload,
      await recipientCertificate.calculateSubjectPrivateAddress(),
    );

    const payloadEnvelopedData = await SessionEnvelopedData.deserialize(payloadSerialized);
    const encryptedContentInfo = payloadEnvelopedData.pkijsEnvelopedData.encryptedContentInfo;
    expect(encryptedContentInfo.contentEncryptionAlgorithm.algorithmId).toEqual(
      CRYPTO_OIDS.AES_CBC_192,
    );
  });
});

describe('unwrapMessagePayload', () => {
  const RECIPIENT_ADDRESS = 'https://example.com';

  let sessionKey: SessionKey;
  beforeEach(async () => {
    const sessionKeyPair = await SessionKeyPair.generate();
    sessionKey = sessionKeyPair.sessionKey;
    await privateKeyStore.saveUnboundSessionKey(
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
      senderCertificate,
      Buffer.from(envelopedData.serialize()),
    );
    const node = new StubNodeManager(privateKeyStore, publicKeyStore);

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
      senderCertificate,
      Buffer.from(envelopedData.serialize()),
    );
    const node = new StubNodeManager(privateKeyStore, publicKeyStore);

    await node.unwrapMessagePayload(message);

    const storedKey = publicKeyStore.keys[await senderCertificate.calculateSubjectPrivateAddress()];
    expect(storedKey.publicKeyCreationTime).toEqual(message.creationDate);
    expectBuffersToEqual(Buffer.from(dhKeyId), storedKey.publicKeyId);
    expectBuffersToEqual(
      await derSerializePublicKey((await envelopedData.getOriginatorKey()).publicKey),
      storedKey.publicKeyDer,
    );
  });
});

class StubNodeManager extends BaseNodeManager<StubPayload> {}
