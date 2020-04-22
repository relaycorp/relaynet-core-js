/* tslint:disable:no-let */

import bufferToArray from 'buffer-to-arraybuffer';

import { arrayToAsyncIterable, asyncIterableToArray } from '../_test_utils';
import { generateRandom64BitValue } from '../crypto_wrappers/_utils';
import {
  EnvelopedData,
  SessionEnvelopedData,
  SessionlessEnvelopedData,
} from '../crypto_wrappers/cms/envelopedData';
import { generateECDHKeyPair, generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { MockPrivateKeyStore, MockPublicKeyStore } from '../keyStores/_testMocks';
import Cargo from '../messages/Cargo';
import { issueGatewayCertificate } from '../pki';
import { Gateway } from './gateway';

const TOMORROW = new Date();
TOMORROW.setDate(TOMORROW.getDate() + 1);

describe('Gateway', () => {
  let CERTIFICATE: Certificate;
  const PRIVATE_KEY_STORE = new MockPrivateKeyStore(true);
  beforeAll(async () => {
    const keyPair = await generateRSAKeyPair();

    CERTIFICATE = await issueGatewayCertificate({
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
      validityEndDate: TOMORROW,
    });

    await PRIVATE_KEY_STORE.registerNodeKey(keyPair.privateKey, CERTIFICATE);
  });

  const MESSAGE = Buffer.from('This is a message to be included in a cargo');

  describe('generateCargoes', () => {
    let RECIPIENT_CERTIFICATE: Certificate;
    beforeAll(async () => {
      const recipientKeyPair = await generateRSAKeyPair();

      RECIPIENT_CERTIFICATE = await issueGatewayCertificate({
        issuerPrivateKey: recipientKeyPair.privateKey,
        subjectPublicKey: recipientKeyPair.publicKey,
        validityEndDate: TOMORROW,
      });
    });

    test('Payload should be encrypted with recipient certificate if there is no existing session', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());

      const cargoesSerialized = await asyncIterableToArray(
        gateway.generateCargoes(
          arrayToAsyncIterable([MESSAGE]),
          RECIPIENT_CERTIFICATE,
          CERTIFICATE.getSerialNumber(),
        ),
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
      expect(cargoPayload).toBeInstanceOf(SessionlessEnvelopedData);
      expect(cargoPayload.getRecipientKeyId()).toEqual(RECIPIENT_CERTIFICATE.getSerialNumber());
    });

    test('Payload should be encrypted with session key if there is an existing session', async () => {
      const publicKeyStore = new MockPublicKeyStore();
      const recipientSessionKeyPair = await generateECDHKeyPair();
      const recipientSessionKeyId = await generateRandom64BitValue();
      await publicKeyStore.saveSessionKey(
        recipientSessionKeyPair.publicKey,
        RECIPIENT_CERTIFICATE,
        new Date(),
      );
      const gateway = new Gateway(PRIVATE_KEY_STORE, publicKeyStore);

      const cargoesSerialized = await asyncIterableToArray(
        gateway.generateCargoes(
          arrayToAsyncIterable([MESSAGE]),
          RECIPIENT_CERTIFICATE,
          CERTIFICATE.getSerialNumber(),
        ),
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
      expect(cargoPayload).toBeInstanceOf(SessionEnvelopedData);
      expect(cargoPayload.getRecipientKeyId()).toEqual(recipientSessionKeyId);
    });

    test('Cargo should be signed with the specified key', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());

      const cargoesSerialized = await asyncIterableToArray(
        gateway.generateCargoes(
          arrayToAsyncIterable([MESSAGE]),
          RECIPIENT_CERTIFICATE,
          CERTIFICATE.getSerialNumber(),
        ),
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      expect(CERTIFICATE.isEqual(cargo.senderCertificate));
    });

    test.todo('Encryption options should be honored if present');

    test.todo('Signature options should be honored if present');

    test('Cargo TTL should default to one week', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());

      const cargoesSerialized = await asyncIterableToArray(
        gateway.generateCargoes(
          arrayToAsyncIterable([MESSAGE]),
          RECIPIENT_CERTIFICATE,
          CERTIFICATE.getSerialNumber(),
        ),
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      const secondsInAWeek = 604800;
      expect(cargo.ttl).toEqual(secondsInAWeek);
    });

    test.todo('Cargo TTL should be customizable');

    test.todo('Cargo TTL should be that of the message with the latest TTL');

    test.todo('Zero cargoes should be output if there are zero messages');

    test.todo('Messages should be encapsulated into as few cargoes as possible');
  });
});
