/* tslint:disable:no-let */

import bufferToArray from 'buffer-to-arraybuffer';

import { arrayToAsyncIterable, asyncIterableToArray } from '../_test_utils';
import { generateRandom64BitValue } from '../crypto_wrappers/_utils';
import {
  EnvelopedData,
  SessionEnvelopedData,
  SessionlessEnvelopedData,
} from '../crypto_wrappers/cms/envelopedData';
import { SignatureOptions } from '../crypto_wrappers/cms/signedData';
import { generateECDHKeyPair, generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { MockPrivateKeyStore, MockPublicKeyStore } from '../keyStores/_testMocks';
import Cargo from '../messages/Cargo';
import Parcel from '../messages/Parcel';
import ServiceMessage from '../messages/payloads/ServiceMessage';
import { issueGatewayCertificate } from '../pki';
import { Gateway } from './gateway';

describe('Gateway', () => {
  const MESSAGE = Buffer.from('This is a message to be included in a cargo');

  const TOMORROW = new Date();
  TOMORROW.setDate(TOMORROW.getDate() + 1);
  TOMORROW.setMilliseconds(0);

  let PRIVATE_KEY: CryptoKey;
  let CERTIFICATE: Certificate;
  beforeAll(async () => {
    const keyPair = await generateRSAKeyPair();
    PRIVATE_KEY = keyPair.privateKey;

    CERTIFICATE = await issueGatewayCertificate({
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
      validityEndDate: TOMORROW,
    });
  });

  let PRIVATE_KEY_STORE: MockPrivateKeyStore;
  beforeEach(async () => {
    PRIVATE_KEY_STORE = new MockPrivateKeyStore();
    await PRIVATE_KEY_STORE.registerNodeKey(PRIVATE_KEY, CERTIFICATE);
  });

  describe('generateCargoes', () => {
    let RECIPIENT_PRIVATE_KEY: CryptoKey;
    let RECIPIENT_CERTIFICATE: Certificate;
    beforeAll(async () => {
      const recipientKeyPair = await generateRSAKeyPair();
      RECIPIENT_PRIVATE_KEY = recipientKeyPair.privateKey;

      RECIPIENT_CERTIFICATE = await issueGatewayCertificate({
        issuerPrivateKey: recipientKeyPair.privateKey,
        subjectPublicKey: recipientKeyPair.publicKey,
        validityEndDate: TOMORROW,
      });
    });

    let RECIPIENT_PUBLIC_SESSION_KEY: CryptoKey;
    let RECIPIENT_PUBLIC_SESSION_KEY_ID: Buffer;
    beforeAll(async () => {
      const recipientSessionKeyPair = await generateECDHKeyPair();
      RECIPIENT_PUBLIC_SESSION_KEY = recipientSessionKeyPair.publicKey;

      RECIPIENT_PUBLIC_SESSION_KEY_ID = Buffer.from(await generateRandom64BitValue());
    });

    test('Cargo recipient should be private address of recipient', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_CERTIFICATE,
        CERTIFICATE.getSerialNumber(),
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      expect(cargo.recipientAddress).toEqual(
        await RECIPIENT_CERTIFICATE.calculateSubjectPrivateAddress(),
      );
    });

    test('Payload should be encrypted with recipient certificate if there is no existing session', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_CERTIFICATE,
        CERTIFICATE.getSerialNumber(),
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
      expect(cargoPayload).toBeInstanceOf(SessionlessEnvelopedData);
      expect(cargoPayload.getRecipientKeyId()).toEqual(RECIPIENT_CERTIFICATE.getSerialNumber());
    });

    test('Payload should be encrypted with session key if there is an existing session', async () => {
      const publicKeyStore = new MockPublicKeyStore();
      await publicKeyStore.saveSessionKey(
        { keyId: RECIPIENT_PUBLIC_SESSION_KEY_ID, publicKey: RECIPIENT_PUBLIC_SESSION_KEY },
        RECIPIENT_CERTIFICATE,
        new Date(),
      );
      const gateway = new Gateway(PRIVATE_KEY_STORE, publicKeyStore);

      const cargoesSerialized = await generateCargoesFromMessages(
        [
          {
            expiryDate: TOMORROW,
            message: MESSAGE,
          },
        ],
        RECIPIENT_CERTIFICATE,
        CERTIFICATE.getSerialNumber(),
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
      expect(cargoPayload).toBeInstanceOf(SessionEnvelopedData);
      expect(cargoPayload.getRecipientKeyId()).toEqual(RECIPIENT_PUBLIC_SESSION_KEY_ID);
    });

    test('New ephemeral session key should be stored when using channel session', async () => {
      const publicKeyStore = new MockPublicKeyStore();
      await publicKeyStore.saveSessionKey(
        { keyId: RECIPIENT_PUBLIC_SESSION_KEY_ID, publicKey: RECIPIENT_PUBLIC_SESSION_KEY },
        RECIPIENT_CERTIFICATE,
        new Date(),
      );
      const gateway = new Gateway(PRIVATE_KEY_STORE, publicKeyStore);

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_CERTIFICATE,
        CERTIFICATE.getSerialNumber(),
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
      const originatorKey = await (cargoPayload as SessionEnvelopedData).getOriginatorKey();
      await expect(
        PRIVATE_KEY_STORE.fetchSessionKey(originatorKey.keyId, RECIPIENT_CERTIFICATE),
      ).toResolve();
    });

    test('Session encryption options should be honored if present', async () => {
      const aesKeySize = 192;
      const publicKeyStore = new MockPublicKeyStore();
      await publicKeyStore.saveSessionKey(
        { keyId: RECIPIENT_PUBLIC_SESSION_KEY_ID, publicKey: RECIPIENT_PUBLIC_SESSION_KEY },
        RECIPIENT_CERTIFICATE,
        new Date(),
      );
      const gateway = new Gateway(PRIVATE_KEY_STORE, publicKeyStore, {
        encryption: { aesKeySize },
      });

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_CERTIFICATE,
        CERTIFICATE.getSerialNumber(),
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
      expect(
        cargoPayload.pkijsEnvelopedData.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId,
      ).toEqual('2.16.840.1.101.3.4.1.26');
    });

    test('Sessionless encryption options should be honored if present', async () => {
      const aesKeySize = 192;
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore(), {
        encryption: { aesKeySize },
      });

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_CERTIFICATE,
        CERTIFICATE.getSerialNumber(),
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
      expect(
        cargoPayload.pkijsEnvelopedData.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId,
      ).toEqual('2.16.840.1.101.3.4.1.26');
    });

    test('Cargo should be signed with the specified key', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_CERTIFICATE,
        CERTIFICATE.getSerialNumber(),
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      expect(CERTIFICATE.isEqual(cargo.senderCertificate));
    });

    test('Signature options should be honored if present', async () => {
      const signatureOptions: SignatureOptions = { hashingAlgorithmName: 'SHA-384' };
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore(), {
        signature: signatureOptions,
      });
      const cargoSerializeSpy = jest.spyOn(Cargo.prototype, 'serialize');

      await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_CERTIFICATE,
        CERTIFICATE.getSerialNumber(),
        gateway,
      );

      expect(cargoSerializeSpy).toBeCalledTimes(1);
      expect(cargoSerializeSpy).toBeCalledWith(expect.anything(), signatureOptions);
    });

    test('Cargo TTL should be that of the message with the latest TTL', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());

      const cargoesSerialized = await generateCargoesFromMessages(
        [
          { message: MESSAGE, expiryDate: TOMORROW },
          { message: MESSAGE, expiryDate: new Date() },
        ],
        RECIPIENT_CERTIFICATE,
        CERTIFICATE.getSerialNumber(),
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      expect(cargo.expiryDate).toEqual(TOMORROW);
    });

    test('Zero cargoes should be output if there are zero messages', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());

      const cargoesSerialized = await generateCargoesFromMessages(
        [],
        RECIPIENT_CERTIFICATE,
        CERTIFICATE.getSerialNumber(),
        gateway,
      );

      expect(cargoesSerialized).toHaveLength(0);
    });

    test('Messages should be encapsulated into as few cargoes as possible', async () => {
      // TODO: REFACTOR
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());
      const mediumSizedServiceMessage = Buffer.from('the payload');
      const serviceMessage = new ServiceMessage('a', mediumSizedServiceMessage);
      const serviceMessageSerialized = await serviceMessage.serialize();
      const serviceMessageEncrypted = await SessionlessEnvelopedData.encrypt(
        serviceMessageSerialized,
        RECIPIENT_CERTIFICATE,
      );
      const payloadSerialized = Buffer.from(serviceMessageEncrypted.serialize());
      const dummyParcel = new Parcel('address', CERTIFICATE, payloadSerialized);
      const dummyParcelSerialized = Buffer.from(await dummyParcel.serialize(PRIVATE_KEY));

      const cargoesSerialized = await generateCargoesFromMessages(
        [
          { message: dummyParcelSerialized, expiryDate: TOMORROW },
          { message: dummyParcelSerialized, expiryDate: TOMORROW },
          { message: dummyParcelSerialized, expiryDate: TOMORROW },
        ],
        RECIPIENT_CERTIFICATE,
        CERTIFICATE.getSerialNumber(),
        gateway,
      );

      expect(cargoesSerialized).toHaveLength(1);
      const messagesInCargo = await extractMessagesFromCargo(cargoesSerialized[0]);
      expect(messagesInCargo).toHaveProperty('size', 3);
      expect(await Parcel.deserialize(Array.from(messagesInCargo)[0])).toHaveProperty(
        'payloadSerialized',
        payloadSerialized,
      );
    });

    async function generateCargoesFromMessages(
      messages: ReadonlyArray<{ readonly expiryDate: Date; readonly message: Buffer }>,
      recipientCertificate: Certificate,
      senderKeyId: Buffer,
      gateway: Gateway,
    ): Promise<readonly Buffer[]> {
      return asyncIterableToArray(
        gateway.generateCargoes(arrayToAsyncIterable(messages), recipientCertificate, senderKeyId),
      );
    }

    async function extractMessagesFromCargo(cargoSerialized: Buffer): Promise<Set<ArrayBuffer>> {
      const recipientPrivateKeyStore = new MockPrivateKeyStore();
      await recipientPrivateKeyStore.registerNodeKey(RECIPIENT_PRIVATE_KEY, RECIPIENT_CERTIFICATE);

      const cargo = await Cargo.deserialize(bufferToArray(cargoSerialized));
      const { payload } = await cargo.unwrapPayload(recipientPrivateKeyStore);
      return payload.messages;
    }
  });
});
