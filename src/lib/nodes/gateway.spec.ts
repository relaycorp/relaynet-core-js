import bufferToArray from 'buffer-to-arraybuffer';
import { addSeconds } from 'date-fns';

import { arrayToAsyncIterable, asyncIterableToArray, CRYPTO_OIDS } from '../_test_utils';
import { EnvelopedData, SessionEnvelopedData } from '../crypto_wrappers/cms/envelopedData';
import { SignatureOptions } from '../crypto_wrappers/cms/SignatureOptions';
import { generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { MockPrivateKeyStore, MockPublicKeyStore } from '../keyStores/testMocks';
import Cargo from '../messages/Cargo';
import Parcel from '../messages/Parcel';
import CargoMessageSet from '../messages/payloads/CargoMessageSet';
import ServiceMessage from '../messages/payloads/ServiceMessage';
import { issueGatewayCertificate } from '../pki';
import { RAMF_MAX_TTL } from '../ramf/serialization';
import { SessionKey } from '../SessionKey';
import { SessionKeyPair } from '../SessionKeyPair';
import { GatewayManager } from './gateway';

describe('Gateway', () => {
  const MESSAGE = Buffer.from('This is a message to be included in a cargo');

  const TOMORROW = new Date();
  TOMORROW.setDate(TOMORROW.getDate() + 1);
  TOMORROW.setMilliseconds(0);

  let senderPrivateKey: CryptoKey;
  let senderCertificate: Certificate;
  beforeAll(async () => {
    const keyPair = await generateRSAKeyPair();
    senderPrivateKey = keyPair.privateKey;

    senderCertificate = await issueGatewayCertificate({
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
      validityEndDate: TOMORROW,
    });
  });

  const PRIVATE_KEY_STORE = new MockPrivateKeyStore();
  beforeEach(async () => {
    PRIVATE_KEY_STORE.clear();
  });

  describe('generateCargoes', () => {
    const RECIPIENT_PRIVATE_ADDRESS = '0deadbeef';

    let recipientSessionKeyPair: SessionKeyPair;
    beforeAll(async () => {
      recipientSessionKeyPair = await SessionKeyPair.generate();
    });

    const PUBLIC_KEY_STORE = new MockPublicKeyStore();
    beforeEach(async () => {
      PUBLIC_KEY_STORE.clear();
      await PUBLIC_KEY_STORE.saveSessionKey(
        recipientSessionKeyPair.sessionKey,
        RECIPIENT_PRIVATE_ADDRESS,
        new Date(),
      );
    });

    test('Recipient address should be private if public address is unset', async () => {
      const gateway = new GatewayManager(PRIVATE_KEY_STORE, PUBLIC_KEY_STORE);

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_PRIVATE_ADDRESS,
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      expect(cargo.recipientAddress).toEqual(RECIPIENT_PRIVATE_ADDRESS);
    });

    test('Recipient address should be specified public one if set', async () => {
      const gateway = new GatewayManager(PRIVATE_KEY_STORE, PUBLIC_KEY_STORE);
      const publicAddress = 'https://gateway.com';

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_PRIVATE_ADDRESS,
        gateway,
        publicAddress,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      expect(cargo.recipientAddress).toEqual(publicAddress);
    });

    test('Payload should be encrypted with session key', async () => {
      const gateway = new GatewayManager(PRIVATE_KEY_STORE, PUBLIC_KEY_STORE);

      const cargoesSerialized = await generateCargoesFromMessages(
        [
          {
            expiryDate: TOMORROW,
            message: MESSAGE,
          },
        ],
        RECIPIENT_PRIVATE_ADDRESS,
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
      expect(cargoPayload).toBeInstanceOf(SessionEnvelopedData);
      expect(cargoPayload.getRecipientKeyId()).toEqual(recipientSessionKeyPair.sessionKey.keyId);
    });

    test('New ephemeral session key should be stored when using channel session', async () => {
      const gateway = new GatewayManager(PRIVATE_KEY_STORE, PUBLIC_KEY_STORE);

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_PRIVATE_ADDRESS,
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      const cargoPayload = EnvelopedData.deserialize(bufferToArray(cargo.payloadSerialized));
      const originatorKey = await (cargoPayload as SessionEnvelopedData).getOriginatorKey();
      await expect(
        PRIVATE_KEY_STORE.retrieveSessionKey(originatorKey.keyId, RECIPIENT_PRIVATE_ADDRESS),
      ).toResolve();
    });

    test('Session encryption options should be honored if present', async () => {
      const aesKeySize = 192;
      const gateway = new GatewayManager(PRIVATE_KEY_STORE, PUBLIC_KEY_STORE, {
        encryption: { aesKeySize },
      });

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_PRIVATE_ADDRESS,
        gateway,
      );

      expect(await getCargoPayloadEncryptionAlgorithmId(cargoesSerialized[0])).toEqual(
        CRYPTO_OIDS.AES_CBC_192,
      );
    });

    test('Sessionless encryption options should be honored if present', async () => {
      const aesKeySize = 192;
      const gateway = new GatewayManager(PRIVATE_KEY_STORE, PUBLIC_KEY_STORE, {
        encryption: { aesKeySize },
      });

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_PRIVATE_ADDRESS,
        gateway,
      );

      expect(await getCargoPayloadEncryptionAlgorithmId(cargoesSerialized[0])).toEqual(
        CRYPTO_OIDS.AES_CBC_192,
      );
    });

    test('Cargo should be signed with the specified key', async () => {
      const gateway = new GatewayManager(PRIVATE_KEY_STORE, PUBLIC_KEY_STORE);

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_PRIVATE_ADDRESS,
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      expect(senderCertificate.isEqual(cargo.senderCertificate)).toBeTrue();
    });

    test('Signature options should be honored if present', async () => {
      const signatureOptions: SignatureOptions = { hashingAlgorithmName: 'SHA-384' };
      const gateway = new GatewayManager(PRIVATE_KEY_STORE, PUBLIC_KEY_STORE, {
        signature: signatureOptions,
      });
      const cargoSerializeSpy = jest.spyOn(Cargo.prototype, 'serialize');

      await generateCargoesFromMessages(
        [{ expiryDate: TOMORROW, message: MESSAGE }],
        RECIPIENT_PRIVATE_ADDRESS,
        gateway,
      );

      expect(cargoSerializeSpy).toBeCalledTimes(1);
      expect(cargoSerializeSpy).toBeCalledWith(expect.anything(), signatureOptions);
    });

    test('Cargo creation date should be 3 hours in the past', async () => {
      const gateway = new GatewayManager(PRIVATE_KEY_STORE, PUBLIC_KEY_STORE);

      const cargoesSerialized = await generateCargoesFromMessages(
        [{ message: MESSAGE, expiryDate: TOMORROW }],
        RECIPIENT_PRIVATE_ADDRESS,
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
      const gateway = new GatewayManager(PRIVATE_KEY_STORE, PUBLIC_KEY_STORE);

      const cargoesSerialized = await generateCargoesFromMessages(
        [
          { message: MESSAGE, expiryDate: TOMORROW },
          { message: MESSAGE, expiryDate: new Date() },
        ],
        RECIPIENT_PRIVATE_ADDRESS,
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      expect(cargo.expiryDate).toEqual(TOMORROW);
    });

    test('Cargo TTL should not exceed maximum RAMF TTL', async () => {
      const gateway = new GatewayManager(PRIVATE_KEY_STORE, PUBLIC_KEY_STORE);

      const now = new Date();
      const cargoesSerialized = await generateCargoesFromMessages(
        [{ message: MESSAGE, expiryDate: addSeconds(now, RAMF_MAX_TTL + 60) }],
        RECIPIENT_PRIVATE_ADDRESS,
        gateway,
      );

      const cargo = await Cargo.deserialize(bufferToArray(cargoesSerialized[0]));
      expect(cargo.ttl).toEqual(RAMF_MAX_TTL);
    });

    test('Zero cargoes should be output if there are zero messages', async () => {
      const gateway = new GatewayManager(PRIVATE_KEY_STORE, PUBLIC_KEY_STORE);

      const cargoesSerialized = await generateCargoesFromMessages(
        [],
        RECIPIENT_PRIVATE_ADDRESS,
        gateway,
      );

      expect(cargoesSerialized).toHaveLength(0);
    });

    test('Messages should be encapsulated into as few cargoes as possible', async () => {
      const gateway = new GatewayManager(PRIVATE_KEY_STORE, PUBLIC_KEY_STORE);
      const dummyParcel = await generateDummyParcel(
        RECIPIENT_PRIVATE_ADDRESS,
        recipientSessionKeyPair.sessionKey,
        senderCertificate,
      );
      const dummyParcelSerialized = await dummyParcel.serialize(senderPrivateKey);

      const cargoesSerialized = await generateCargoesFromMessages(
        [
          { message: Buffer.from(dummyParcelSerialized), expiryDate: TOMORROW },
          { message: Buffer.from(dummyParcelSerialized), expiryDate: TOMORROW },
          { message: Buffer.from(dummyParcelSerialized), expiryDate: TOMORROW },
        ],
        RECIPIENT_PRIVATE_ADDRESS,
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
      recipientPrivateAddress1: string,
      gateway: GatewayManager,
      recipientPublicAddress?: string,
    ): Promise<readonly Buffer[]> {
      return asyncIterableToArray(
        gateway.generateCargoes(
          arrayToAsyncIterable(messages),
          recipientPrivateAddress1,
          senderPrivateKey,
          senderCertificate,
          recipientPublicAddress,
        ),
      );
    }

    async function extractMessageSetFromCargo(cargoSerialized: Buffer): Promise<CargoMessageSet> {
      const cargo = await Cargo.deserialize(bufferToArray(cargoSerialized));
      const { payload } = await cargo.unwrapPayload(recipientSessionKeyPair.privateKey);
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
  recipientAddress: string,
  recipientSessionKey: SessionKey,
  senderCertificate: Certificate,
): Promise<Parcel> {
  const serviceMessage = new ServiceMessage('a', Buffer.from('the payload'));
  const serviceMessageSerialized = await serviceMessage.serialize();
  const { envelopedData } = await SessionEnvelopedData.encrypt(
    serviceMessageSerialized,
    recipientSessionKey,
  );
  const payloadSerialized = Buffer.from(envelopedData.serialize());
  return new Parcel(recipientAddress, senderCertificate, payloadSerialized);
}
