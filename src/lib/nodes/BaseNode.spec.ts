import { arrayBufferFrom, expectBuffersToEqual } from '../_test_utils';
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
import { BaseNode } from './BaseNode';

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

describe('unwrapMessagePayload', () => {
  const payloadPlaintextContent = arrayBufferFrom('content');

  let publicKeyStore: MockPublicKeyStore;
  beforeEach(() => {
    publicKeyStore = new MockPublicKeyStore();
  });

  const RECIPIENT_ADDRESS = 'https://example.com';

  test('Payload plaintext should be returned when using sessionless encryption', async () => {
    const payload = await SessionlessEnvelopedData.encrypt(
      payloadPlaintextContent,
      recipientCertificate,
    );
    const message = new StubMessage(
      RECIPIENT_ADDRESS,
      senderCertificate,
      Buffer.from(payload.serialize()),
    );
    const node = new StubNode(privateKeyStore, publicKeyStore);

    const payloadPlaintext = await node.unwrapMessagePayload(message);

    expectBuffersToEqual(payloadPlaintext.content, payloadPlaintextContent);
    expect(publicKeyStore.keys).toBeEmpty();
  });

  test('Payload plaintext should be returned and session key stored when using a session', async () => {
    const sessionKeyPair = await generateECDHKeyPair();
    const sessionKeyId = Buffer.from('key id');
    await privateKeyStore.registerInitialSessionKey(sessionKeyPair.privateKey, sessionKeyId);
    const encryptionResult = await SessionEnvelopedData.encrypt(payloadPlaintextContent, {
      keyId: sessionKeyId,
      publicKey: sessionKeyPair.publicKey,
    });
    const message = new StubMessage(
      RECIPIENT_ADDRESS,
      senderCertificate,
      Buffer.from(encryptionResult.envelopedData.serialize()),
    );
    const node = new StubNode(privateKeyStore, publicKeyStore);

    const payloadPlaintext = await node.unwrapMessagePayload(message);

    expectBuffersToEqual(payloadPlaintext.content, payloadPlaintextContent);

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

class StubNode extends BaseNode<StubPayload> {}
