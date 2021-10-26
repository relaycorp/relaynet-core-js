import bufferToArray from 'buffer-to-arraybuffer';

import { arrayToAsyncIterable, asyncIterableToArray, CRYPTO_OIDS } from '../_test_utils';
import { generateRandom64BitValue } from '../crypto_wrappers/_utils';
import {
  EnvelopedData,
  SessionEnvelopedData,
  SessionlessEnvelopedData,
} from '../crypto_wrappers/cms/envelopedData';
import { SignatureOptions } from '../crypto_wrappers/cms/SignatureOptions';
import { generateECDHKeyPair, generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { MockPrivateKeyStore, MockPublicKeyStore } from '../keyStores/testMocks';
import Cargo from '../messages/Cargo';
import Parcel from '../messages/Parcel';
import CargoMessageSet from '../messages/payloads/CargoMessageSet';
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

    test('Recipient address should be private if public address is unset', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_CERTIFICATE,
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      expect(cargo.recipientAddress).toEqual(
        await RECIPIENT_CERTIFICATE.calculateSubjectPrivateAddress(),
      );
    });

    test('Recipient address should be specified public one if set', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());
      const publicAddress = 'https://gateway.com';

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_CERTIFICATE,
        gateway,
        publicAddress,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      expect(cargo.recipientAddress).toEqual(publicAddress);
    });

    test('Payload should be encrypted with recipient certificate if there is no session', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_CERTIFICATE,
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
      expect(cargoPayload).toBeInstanceOf(SessionlessEnvelopedData);
      expect(cargoPayload.getRecipientKeyId()).toEqual(RECIPIENT_CERTIFICATE.getSerialNumber());
    });

    test('Payload should be encrypted with session key if there is a session', async () => {
      const publicKeyStore = new MockPublicKeyStore();
      await publicKeyStore.saveSessionKey(
        { keyId: RECIPIENT_PUBLIC_SESSION_KEY_ID, publicKey: RECIPIENT_PUBLIC_SESSION_KEY },
        await RECIPIENT_CERTIFICATE.calculateSubjectPrivateAddress(),
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
        await RECIPIENT_CERTIFICATE.calculateSubjectPrivateAddress(),
        new Date(),
      );
      const gateway = new Gateway(PRIVATE_KEY_STORE, publicKeyStore);

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_CERTIFICATE,
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
      const originatorKey = await (cargoPayload as SessionEnvelopedData).getOriginatorKey();
      await expect(
        PRIVATE_KEY_STORE.fetchSessionKey(
          originatorKey.keyId,
          await RECIPIENT_CERTIFICATE.calculateSubjectPrivateAddress(),
        ),
      ).toResolve();
    });

    test('Session encryption options should be honored if present', async () => {
      const aesKeySize = 192;
      const publicKeyStore = new MockPublicKeyStore();
      await publicKeyStore.saveSessionKey(
        { keyId: RECIPIENT_PUBLIC_SESSION_KEY_ID, publicKey: RECIPIENT_PUBLIC_SESSION_KEY },
        await RECIPIENT_CERTIFICATE.calculateSubjectPrivateAddress(),
        new Date(),
      );
      const gateway = new Gateway(PRIVATE_KEY_STORE, publicKeyStore, {
        encryption: { aesKeySize },
      });

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_CERTIFICATE,
        gateway,
      );

      expect(await getCargoPayloadEncryptionAlgorithmId(cargoesSerialized[0])).toEqual(
        CRYPTO_OIDS.AES_CBC_192,
      );
    });

    test('Sessionless encryption options should be honored if present', async () => {
      const aesKeySize = 192;
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore(), {
        encryption: { aesKeySize },
      });

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_CERTIFICATE,
        gateway,
      );

      expect(await getCargoPayloadEncryptionAlgorithmId(cargoesSerialized[0])).toEqual(
        CRYPTO_OIDS.AES_CBC_192,
      );
    });

    test('Cargo should be signed with the specified key', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_CERTIFICATE,
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      expect(CERTIFICATE.isEqual(cargo.senderCertificate)).toBeTrue();
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
        gateway,
      );

      expect(cargoSerializeSpy).toBeCalledTimes(1);
      expect(cargoSerializeSpy).toBeCalledWith(expect.anything(), signatureOptions);
    });

    test('Cargo creation date should be 3 hours in the past', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ message: MESSAGE, expiryDate: TOMORROW }],
        RECIPIENT_CERTIFICATE,
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      const expectedCreationDate = new Date();
      expectedCreationDate.setHours(expectedCreationDate.getHours() - 3);
      expect(cargo.creationDate.getTime()).toBeWithin(
        expectedCreationDate.getTime() - 5_000,
        expectedCreationDate.getTime() + 5_000,
      );
    });

    test('Cargo TTL should be that of the message with the latest TTL', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());

      const cargoesSerialized = await generateCargoesFromMessages(
        [
          { message: MESSAGE, expiryDate: TOMORROW },
          { message: MESSAGE, expiryDate: new Date() },
        ],
        RECIPIENT_CERTIFICATE,
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
        gateway,
      );

      expect(cargoesSerialized).toHaveLength(0);
    });

    test('Messages should be encapsulated into as few cargoes as possible', async () => {
      const gateway = new Gateway(PRIVATE_KEY_STORE, new MockPublicKeyStore());
      const dummyParcel = await generateDummyParcel(RECIPIENT_CERTIFICATE, CERTIFICATE);
      const dummyParcelSerialized = await dummyParcel.serialize(PRIVATE_KEY);

      const cargoesSerialized = await generateCargoesFromMessages(
        [
          { message: Buffer.from(dummyParcelSerialized), expiryDate: TOMORROW },
          { message: Buffer.from(dummyParcelSerialized), expiryDate: TOMORROW },
          { message: Buffer.from(dummyParcelSerialized), expiryDate: TOMORROW },
        ],
        RECIPIENT_CERTIFICATE,
        gateway,
      );

      expect(cargoesSerialized).toHaveLength(1);
      const messageSet = await extractMessageSetFromCargo(cargoesSerialized[0]);
      expect(messageSet.messages.length).toEqual(3);
      expect(Array.from(messageSet.messages)).toEqual([
        dummyParcelSerialized,
        dummyParcelSerialized,
        dummyParcelSerialized,
      ]);
    });

    async function generateCargoesFromMessages(
      messages: ReadonlyArray<{ readonly expiryDate: Date; readonly message: Buffer }>,
      recipientCertificate: Certificate,
      gateway: Gateway,
      recipientPublicAddress?: string,
    ): Promise<readonly Buffer[]> {
      return asyncIterableToArray(
        gateway.generateCargoes(
          arrayToAsyncIterable(messages),
          recipientCertificate,
          PRIVATE_KEY,
          CERTIFICATE,
          recipientPublicAddress,
        ),
      );
    }

    async function extractMessageSetFromCargo(cargoSerialized: Buffer): Promise<CargoMessageSet> {
      const recipientPrivateKeyStore = new MockPrivateKeyStore();
      await recipientPrivateKeyStore.registerNodeKey(RECIPIENT_PRIVATE_KEY, RECIPIENT_CERTIFICATE);

      const cargo = await Cargo.deserialize(bufferToArray(cargoSerialized));
      const { payload } = await cargo.unwrapPayload(recipientPrivateKeyStore);
      return payload;
    }

    async function getCargoPayloadEncryptionAlgorithmId(cargoSerialized: Buffer): Promise<string> {
      const cargo = await Cargo.deserialize(bufferToArray(cargoSerialized));
      const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
      const encryptedContentInfo = cargoPayload.pkijsEnvelopedData.encryptedContentInfo;
      return encryptedContentInfo.contentEncryptionAlgorithm.algorithmId;
    }
  });
});

async function generateDummyParcel(
  recipientCertificate: Certificate,
  senderCertificate: Certificate,
): Promise<Parcel> {
  const serviceMessage = new ServiceMessage('a', Buffer.from('the payload'));
  const serviceMessageSerialized = await serviceMessage.serialize();
  const serviceMessageEncrypted = await SessionlessEnvelopedData.encrypt(
    serviceMessageSerialized,
    recipientCertificate,
  );
  const payloadSerialized = Buffer.from(serviceMessageEncrypted.serialize());
  return new Parcel(
    await recipientCertificate.calculateSubjectPrivateAddress(),
    senderCertificate,
    payloadSerialized,
  );
}
