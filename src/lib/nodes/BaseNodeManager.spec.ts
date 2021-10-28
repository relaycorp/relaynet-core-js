import { arrayBufferFrom, CRYPTO_OIDS, expectBuffersToEqual } from '../_test_utils';
import {
  SessionEnvelopedData,
  SessionlessEnvelopedData,
} from '../crypto_wrappers/cms/envelopedData';
import {
  derSerializePublicKey,
  generateECDHKeyPair,
  generateRSAKeyPair,
} from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { MockPrivateKeyStore, MockPublicKeyStore } from '../keyStores/testMocks';
import { issueGatewayCertificate } from '../pki';
import { StubMessage, StubPayload } from '../ramf/_test_utils';
import { SessionKey } from '../SessionKey';
import { BaseNodeManager } from './BaseNodeManager';
import { NodeError } from './errors';

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

let recipientCertificate: Certificate;
let privateKeyStore: MockPrivateKeyStore;
beforeAll(async () => {
  const recipientKeyPair = await generateRSAKeyPair();

  recipientCertificate = await issueGatewayCertificate({
    issuerPrivateKey: recipientKeyPair.privateKey,
    subjectPublicKey: recipientKeyPair.publicKey,
    validityEndDate: TOMORROW,
  });

  privateKeyStore = new MockPrivateKeyStore();
  await privateKeyStore.registerNodeKey(recipientKeyPair.privateKey, recipientCertificate);
});

let publicKeyStore: MockPublicKeyStore;
beforeEach(() => {
  publicKeyStore = new MockPublicKeyStore();
});

const PAYLOAD_PLAINTEXT_CONTENT = arrayBufferFrom('payload content');

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
      privateKeyStore.fetchSessionKey(
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

  test('Payload plaintext should be returned when using sessionless encryption', async () => {
    const payload = await SessionlessEnvelopedData.encrypt(
      PAYLOAD_PLAINTEXT_CONTENT,
      recipientCertificate,
    );
    const message = new StubMessage(
      RECIPIENT_ADDRESS,
      senderCertificate,
      Buffer.from(payload.serialize()),
    );
    const node = new StubNodeManager(privateKeyStore, publicKeyStore);

    const payloadPlaintext = await node.unwrapMessagePayload(message);

    expectBuffersToEqual(payloadPlaintext.content, PAYLOAD_PLAINTEXT_CONTENT);
    expect(publicKeyStore.keys).toBeEmpty();
  });

  test('Payload plaintext should be returned and session key stored when using a session', async () => {
    const sessionKeyPair = await generateECDHKeyPair();
    const sessionKeyId = Buffer.from('key id');
    await privateKeyStore.registerInitialSessionKey(sessionKeyPair.privateKey, sessionKeyId);
    const encryptionResult = await SessionEnvelopedData.encrypt(PAYLOAD_PLAINTEXT_CONTENT, {
      keyId: sessionKeyId,
      publicKey: sessionKeyPair.publicKey,
    });
    const message = new StubMessage(
      RECIPIENT_ADDRESS,
      senderCertificate,
      Buffer.from(encryptionResult.envelopedData.serialize()),
    );
    const node = new StubNodeManager(privateKeyStore, publicKeyStore);

    const payloadPlaintext = await node.unwrapMessagePayload(message);

    expectBuffersToEqual(payloadPlaintext.content, PAYLOAD_PLAINTEXT_CONTENT);

    const storedKey = publicKeyStore.keys[await senderCertificate.calculateSubjectPrivateAddress()];
    expect(storedKey.publicKeyCreationTime).toEqual(message.creationDate);
    expectBuffersToEqual(Buffer.from(encryptionResult.dhKeyId), storedKey.publicKeyId);
    expectBuffersToEqual(
      await derSerializePublicKey(
        (
          await encryptionResult.envelopedData.getOriginatorKey()
        ).publicKey,
      ),
      storedKey.publicKeyDer,
    );
  });
});

class StubNodeManager extends BaseNodeManager<StubPayload> {}
