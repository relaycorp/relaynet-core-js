/* tslint:disable:no-let no-object-mutation */
import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';

import {
  arrayBufferFrom,
  arrayToAsyncIterable,
  asyncIterableToArray,
  expectBuffersToEqual,
  generateStubCert,
} from '../../_test_utils';
import { deserializeDer } from '../../crypto_wrappers/_utils';
import { generateRSAKeyPair } from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { MAX_SDU_PLAINTEXT_LENGTH } from '../../ramf/serialization';
import Cargo from '../Cargo';
import InvalidMessageError from '../InvalidMessageError';
import Parcel from '../Parcel';
import CargoMessageSet from './CargoMessageSet';

const STUB_MESSAGE = arrayBufferFrom('hiya');

describe('CargoMessageSet', () => {
  describe('deserialize', () => {
    test('Non-DER-encoded values should be refused', () => {
      const invalidSerialization = bufferToArray(Buffer.from('I pretend to be valid'));

      expect(() => CargoMessageSet.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Serialization is not a valid CargoMessageSet',
      );
    });

    test('Outer value should be an ASN.1 SET', () => {
      const asn1Integer = new asn1js.Integer({ value: 1 });
      const invalidSerialization = asn1Integer.toBER(false);

      expect(() => CargoMessageSet.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Serialization is not a valid CargoMessageSet',
      );
    });

    test('Inner value should be an ASN.1 BIT STRING', () => {
      const asn1Set = new asn1js.Set();
      // tslint:disable-next-line:no-object-mutation
      asn1Set.valueBlock.value = [new asn1js.Integer({ value: 1 })];
      const invalidSerialization = asn1Set.toBER(false);

      expect(() => CargoMessageSet.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Serialization is not a valid CargoMessageSet',
      );
    });

    test('A set without values should be treated as an empty set', () => {
      const asn1Set = new asn1js.Set();
      const serialization = asn1Set.toBER(false);

      const cargoMessages = CargoMessageSet.deserialize(serialization);
      expect(cargoMessages.messages).toEqual(new Set());
    });

    test('An empty set should be accepted', () => {
      const asn1Set = new asn1js.Set();
      asn1Set.valueBlock.value = [];
      const serialization = asn1Set.toBER(false);

      const cargoMessages = CargoMessageSet.deserialize(serialization);
      expect(cargoMessages.messages).toEqual(new Set());
    });

    test('A single-item set should be accepted', () => {
      const asn1Set = new asn1js.Set();
      asn1Set.valueBlock.value = [new asn1js.BitString({ valueHex: STUB_MESSAGE })];
      const serialization = asn1Set.toBER(false);

      const cargoMessages = CargoMessageSet.deserialize(serialization);
      expect(cargoMessages.messages).toEqual(new Set([STUB_MESSAGE]));
    });

    test('A multi-item set should be accepted', () => {
      const messages: readonly ArrayBuffer[] = [STUB_MESSAGE, arrayBufferFrom('another message')];
      const asn1Set = new asn1js.Set();
      asn1Set.valueBlock.value = messages.map(m => new asn1js.BitString({ valueHex: m }));
      const serialization = asn1Set.toBER(false);

      const cargoMessages = CargoMessageSet.deserialize(serialization);
      expect(cargoMessages.messages).toEqual(new Set(messages));
    });
  });

  describe('batchMessagesSerialized', () => {
    test('Zero messages should result in zero batches', async () => {
      const messages = arrayToAsyncIterable([]);

      const batches = await asyncIterableToArray(CargoMessageSet.batchMessagesSerialized(messages));

      expect(batches).toHaveLength(0);
    });

    test('A single message should result in one batch', async () => {
      const messagesSerialized: readonly ArrayBuffer[] = [arrayBufferFrom('I am a parcel.')];
      const messages = arrayToAsyncIterable(messagesSerialized);

      const batches = await asyncIterableToArray(CargoMessageSet.batchMessagesSerialized(messages));

      expect(batches).toHaveLength(1);
      const messageSet = CargoMessageSet.deserialize(batches[0]);
      expect(messageSet.messages).toEqual(new Set(messagesSerialized));
    });

    test('Multiple small messages should be put in the same batch', async () => {
      const messagesSerialized: readonly ArrayBuffer[] = [
        arrayBufferFrom('I am a parcel.'),
        arrayBufferFrom('And I am also a parcel.'),
      ];
      const messages = arrayToAsyncIterable(messagesSerialized);

      const batches = await asyncIterableToArray(CargoMessageSet.batchMessagesSerialized(messages));

      expect(batches).toHaveLength(1);
      const messageSet = CargoMessageSet.deserialize(batches[0]);
      expect(messageSet.messages).toEqual(new Set(messagesSerialized));
    });

    test('Messages should be put into as few batches as possible', async () => {
      const octetsIn3Mib = 3145728;
      const messageSerialized = arrayBufferFrom('a'.repeat(octetsIn3Mib));
      const messages = arrayToAsyncIterable([
        messageSerialized,
        messageSerialized,
        messageSerialized,
      ]);

      const batches = await asyncIterableToArray(CargoMessageSet.batchMessagesSerialized(messages));

      expect(batches).toHaveLength(2);
      const messageSet1 = CargoMessageSet.deserialize(batches[0]);
      expect(messageSet1.messages).toEqual(new Set([messageSerialized, messageSerialized]));
      const messageSet2 = CargoMessageSet.deserialize(batches[1]);
      expect(messageSet2.messages).toEqual(new Set([messageSerialized]));
    });

    test('Messages exceeding the max per-message size should be refused', async () => {
      const messageSerialized = arrayBufferFrom('a'.repeat(CargoMessageSet.MAX_MESSAGE_LENGTH + 1));
      const messages = arrayToAsyncIterable([messageSerialized]);

      await expect(
        asyncIterableToArray(CargoMessageSet.batchMessagesSerialized(messages)),
      ).rejects.toEqual(
        new InvalidMessageError(
          `Cargo messages must not exceed ${CargoMessageSet.MAX_MESSAGE_LENGTH} octets ` +
            `(got one with ${messageSerialized.byteLength} octets)`,
        ),
      );
    });

    test('A message with the largest possible length should be included', async () => {
      const messageSerialized = arrayBufferFrom('a'.repeat(CargoMessageSet.MAX_MESSAGE_LENGTH));
      const messages = arrayToAsyncIterable([messageSerialized]);

      const batches = await asyncIterableToArray(CargoMessageSet.batchMessagesSerialized(messages));

      expect(batches).toHaveLength(1);
      expect(batches[0].byteLength).toEqual(MAX_SDU_PLAINTEXT_LENGTH);
      const messageSet = CargoMessageSet.deserialize(batches[0]);
      expect(messageSet.messages).toEqual(new Set([messageSerialized]));
    });

    test('Messages collectively reaching max length should be placed together', async () => {
      const messageSerialized1 = arrayBufferFrom(
        'a'.repeat(Math.floor(CargoMessageSet.MAX_MESSAGE_LENGTH / 2) - 3),
      );
      const messageSerialized2 = arrayBufferFrom(
        'a'.repeat(Math.ceil(CargoMessageSet.MAX_MESSAGE_LENGTH / 2) - 3),
      );
      const messages = arrayToAsyncIterable([messageSerialized1, messageSerialized2]);

      const batches = await asyncIterableToArray(CargoMessageSet.batchMessagesSerialized(messages));

      expect(batches).toHaveLength(1);
      expect(batches[0].byteLength).toEqual(MAX_SDU_PLAINTEXT_LENGTH);
      const messageSet = CargoMessageSet.deserialize(batches[0]);
      expect(messageSet.messages).toEqual(new Set([messageSerialized1, messageSerialized2]));
    });
  });

  describe('serialize', () => {
    test('An empty set should serialized as such', () => {
      const payload = new CargoMessageSet(new Set([]));

      const serialization = payload.serialize();

      const deserialization = deserializeDer(serialization);
      expect(deserialization).toBeInstanceOf(asn1js.Set);
      expect((deserialization as asn1js.Set).valueBlock.value).toHaveLength(0);
    });

    test('A one-item set should serialized as such', () => {
      const payload = new CargoMessageSet(new Set([STUB_MESSAGE]));

      const serialization = payload.serialize();

      const deserialization = deserializeDer(serialization);
      expect(deserialization).toBeInstanceOf(asn1js.Set);

      expect((deserialization as asn1js.Set).valueBlock.value).toHaveLength(1);
      const stubMessageAsn1 = (deserialization as asn1js.Set).valueBlock.value[0];
      expect(stubMessageAsn1).toBeInstanceOf(asn1js.BitString);
      expectBuffersToEqual((stubMessageAsn1 as asn1js.BitString).valueBlock.valueHex, STUB_MESSAGE);
    });

    test('A multi-item set should serialized as such', () => {
      const stubMessages: readonly ArrayBuffer[] = [STUB_MESSAGE, arrayBufferFrom('bye')];
      const payload = new CargoMessageSet(new Set(stubMessages));

      const serialization = payload.serialize();

      const deserialization = deserializeDer(serialization);
      expect(deserialization).toBeInstanceOf(asn1js.Set);

      expect((deserialization as asn1js.Set).valueBlock.value).toHaveLength(stubMessages.length);
      for (let index = 0; index < stubMessages.length; index++) {
        const messageAsn1 = (deserialization as asn1js.Set).valueBlock.value[index];
        expect(messageAsn1).toBeInstanceOf(asn1js.BitString);
        expectBuffersToEqual(
          (messageAsn1 as asn1js.BitString).valueBlock.valueHex,
          stubMessages[index],
        );
      }
    });
  });

  describe('deserializeMessages', () => {
    let privateKey: CryptoKey;
    let certificate: Certificate;

    beforeAll(async () => {
      const senderKeyPair = await generateRSAKeyPair();
      privateKey = senderKeyPair.privateKey;
      certificate = await generateStubCert({
        issuerPrivateKey: privateKey,
        subjectPublicKey: senderKeyPair.publicKey,
      });
    });

    test('Parcels should be yielded', async () => {
      const parcel = new Parcel('address', certificate, Buffer.from('hi'));
      const parcelSerialization = await parcel.serialize(privateKey);
      const cargoMessageSet = new CargoMessageSet(new Set([parcelSerialization]));

      const messages = await asyncIterableToArray(cargoMessageSet.deserializeMessages());

      expect(messages).toHaveLength(1);
      expect(messages[0]).toBeInstanceOf(Parcel);
      expect(messages[0]).toHaveProperty('recipientAddress', parcel.recipientAddress);
    });

    test('An error should be thrown when non-RAMF messages are found', async () => {
      const cargoMessageSet = new CargoMessageSet(new Set([arrayBufferFrom('Not RAMF')]));

      await expect(
        asyncIterableToArray(cargoMessageSet.deserializeMessages()),
      ).rejects.toMatchObject<Partial<InvalidMessageError>>({
        message: expect.stringMatching(
          /^Invalid message found: Serialization starts with invalid RAMF format signature/,
        ),
      });
    });

    test('An error should be thrown when unsupported RAMF messages are found', async () => {
      const innerCargo = new Cargo('address', certificate, Buffer.from('hi'));
      const cargoSerialization = await innerCargo.serialize(privateKey);
      const cargoMessageSet = new CargoMessageSet(new Set([cargoSerialization]));

      await expect(
        asyncIterableToArray(cargoMessageSet.deserializeMessages()),
      ).rejects.toMatchObject<Partial<InvalidMessageError>>({
        message: expect.stringMatching(/^Invalid message found: Expected concrete message type/),
      });
    });

    test('An empty set should result in no yielded values', async () => {
      const cargoMessageSet = new CargoMessageSet(new Set([]));

      await expect(asyncIterableToArray(cargoMessageSet.deserializeMessages())).resolves.toEqual(
        [],
      );
    });
  });
});
