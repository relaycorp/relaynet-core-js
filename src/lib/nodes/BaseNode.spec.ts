/* tslint:disable:no-let */
import bufferToArray from 'buffer-to-arraybuffer';

import { castMock, generateStubCert, MockMessage } from '../_test_utils';
import {
  SessionEnvelopedData,
  SessionlessEnvelopedData,
} from '../crypto_wrappers/cms/envelopedData';
import { generateECDHKeyPair, generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import Message from '../messages/Message';
import { issueEndpointCertificate, issueInitialDHKeyCertificate } from '../pki';
import { PrivateKeyStore } from '../privateKeyStore';
import BaseNode from './BaseNode';

const STUB_PAYLOAD_PLAINTEXT = Buffer.from('I am the payload plaintext');

const TOMORROW = new Date();
TOMORROW.setDate(TOMORROW.getDate() + 1);

let senderCertificate: Certificate;
let recipientPrivateKey: CryptoKey;
let recipientCertificate: Certificate;
beforeAll(async () => {
  const senderKeyPair = await generateRSAKeyPair();
  senderCertificate = await generateStubCert({
    issuerPrivateKey: senderKeyPair.privateKey,
    subjectPublicKey: senderKeyPair.publicKey,
  });

  const recipientKeyPair = await generateRSAKeyPair();
  recipientPrivateKey = recipientKeyPair.privateKey;
  recipientCertificate = await issueEndpointCertificate({
    issuerPrivateKey: recipientKeyPair.privateKey,
    subjectPublicKey: recipientKeyPair.publicKey,
    validityEndDate: TOMORROW,
  });
});

describe('BaseNode', () => {
  describe('decryptPayload', () => {
    test('SessionlessEnvelopedData value should be decrypted with the right key', async () => {
      const envelopedData = await SessionlessEnvelopedData.encrypt(
        STUB_PAYLOAD_PLAINTEXT,
        recipientCertificate,
      );

      const keyStore = castMock<PrivateKeyStore>({
        fetchNodeKey: jest.fn().mockResolvedValue(recipientPrivateKey),
      });

      const node = new MockNode(keyStore);
      const stubMessage = new MockMessage(
        '0123',
        senderCertificate,
        Buffer.from(envelopedData.serialize()),
      );

      const payloadPlaintext = await node.publicDecryptPayload(stubMessage);

      expect(payloadPlaintext).toEqual(bufferToArray(STUB_PAYLOAD_PLAINTEXT));
      expect(keyStore.fetchNodeKey).toBeCalledWith(recipientCertificate.getSerialNumber());
    });

    test('SessionEnvelopedData value should be decrypted with the right key', async () => {
      const recipientDhKeyPair = await generateECDHKeyPair();
      const recipientDhCertificate = await issueInitialDHKeyCertificate({
        issuerCertificate: recipientCertificate,
        issuerPrivateKey: recipientPrivateKey,
        subjectPublicKey: recipientDhKeyPair.publicKey,
        validityEndDate: TOMORROW,
      });
      const { envelopedData } = await SessionEnvelopedData.encrypt(
        STUB_PAYLOAD_PLAINTEXT,
        recipientDhCertificate,
      );

      const keyStore = castMock<PrivateKeyStore>({
        fetchSessionKey: jest.fn().mockResolvedValue(recipientDhKeyPair.privateKey),
      });

      const node = new MockNode(keyStore);
      const stubMessage = new MockMessage(
        '0123',
        senderCertificate,
        Buffer.from(envelopedData.serialize()),
      );

      const payloadPlaintext = await node.publicDecryptPayload(stubMessage);

      expect(payloadPlaintext).toEqual(bufferToArray(STUB_PAYLOAD_PLAINTEXT));
      expect(keyStore.fetchSessionKey).toBeCalledWith(
        recipientDhCertificate.getSerialNumber(),
        senderCertificate,
      );
    });
  });
});

class MockNode extends BaseNode<MockMessage> {
  public async publicDecryptPayload(message: Message): Promise<ArrayBuffer> {
    return this.decryptPayload(message);
  }
}
