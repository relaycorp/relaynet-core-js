/* tslint:disable:no-object-mutation */
import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';

import {
  arrayBufferFrom,
  arrayToAsyncIterable,
  asyncIterableToArray,
  expectArrayBuffersToEqual,
  generateStubCert,
} from '../../_test_utils';
import { derDeserialize } from '../../crypto_wrappers/_utils';
import { generateRSAKeyPair } from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { CertificationPath } from '../../pki/CertificationPath';
import { MAX_SDU_PLAINTEXT_LENGTH } from '../../ramf/serialization';
import Cargo from '../Cargo';
import { CertificateRotation } from '../CertificateRotation';
import InvalidMessageError from '../InvalidMessageError';
import Parcel from '../Parcel';
import { ParcelCollectionAck } from '../ParcelCollectionAck';
import CargoMessageSet, { MessageWithExpiryDate } from './CargoMessageSet';

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

    test('Outer value should be an ASN.1 SEQUENCE', () => {
      const asn1Integer = new asn1js.Integer({ value: 1 });
      const invalidSerialization = asn1Integer.toBER(false);

      expect(() => CargoMessageSet.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Serialization is not a valid CargoMessageSet',
      );
    });

    test('Inner value should be an ASN.1 OCTET STRING', () => {
      const asn1Sequence = new asn1js.Sequence();
      // tslint:disable-next-line:no-object-mutation
      asn1Sequence.valueBlock.value = [new asn1js.Integer({ value: 1 })];
      const invalidSerialization = asn1Sequence.toBER(false);

      expect(() => CargoMessageSet.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Serialization is not a valid CargoMessageSet',
      );
    });

    test('A sequence without values should be treated as an empty array', () => {
      const asn1Sequence = new asn1js.Sequence();
      const serialization = asn1Sequence.toBER(false);

      const cargoMessages = CargoMessageSet.deserialize(serialization);
      expect(cargoMessages.messages).toEqual([]);
    });

    test('An empty sequence should be accepted', () => {
      const asn1Sequence = new asn1js.Sequence();
      asn1Sequence.valueBlock.value = [];
      const serialization = asn1Sequence.toBER(false);

      const cargoMessages = CargoMessageSet.deserialize(serialization);
      expect(cargoMessages.messages).toEqual([]);
    });

    test('A single-item sequence should be accepted', () => {
      const asn1Sequence = new asn1js.Sequence();
      asn1Sequence.valueBlock.value = [new asn1js.OctetString({ valueHex: STUB_MESSAGE })];
      const serialization = asn1Sequence.toBER(false);

      const cargoMessages = CargoMessageSet.deserialize(serialization);
      expect(cargoMessages.messages).toEqual([STUB_MESSAGE]);
    });

    test('A multi-item sequence should be accepted', () => {
      const messages: readonly ArrayBuffer[] = [STUB_MESSAGE, arrayBufferFrom('another message')];
      const asn1Sequence = new asn1js.Sequence();
      asn1Sequence.valueBlock.value = messages.map((m) => new asn1js.OctetString({ valueHex: m }));
      const serialization = asn1Sequence.toBER(false);

      const cargoMessages = CargoMessageSet.deserialize(serialization);
      expect(cargoMessages.messages).toEqual(messages);
    });
  });

  describe('deserializeItem', () => {
    let privateKey: CryptoKey;
    let certificate: Certificate;

    const PCA = new ParcelCollectionAck('0deadc0de', 'deadbeef', 'parcel-id');

    beforeAll(async () => {
      const senderKeyPair = await generateRSAKeyPair();
      privateKey = senderKeyPair.privateKey;
      certificate = await generateStubCert({
        issuerPrivateKey: privateKey,
        subjectPublicKey: senderKeyPair.publicKey,
      });
    });

    test('Parcels should be returned', async () => {
      const parcel = new Parcel({ id: '0deadbeef' }, certificate, Buffer.from('hi'));
      const parcelSerialization = await parcel.serialize(privateKey);

      const item = await CargoMessageSet.deserializeItem(parcelSerialization);

      expect(item).toBeInstanceOf(Parcel);
      expect(item).toHaveProperty('id', parcel.id);
    });

    test('PCAs should be returned', async () => {
      const item = await CargoMessageSet.deserializeItem(await PCA.serialize());

      expect(item).toBeInstanceOf(ParcelCollectionAck);
      expect(item).toMatchObject(PCA);
    });

    test('Certificate rotations should be returned', async () => {
      const rotation = new CertificateRotation(new CertificationPath(certificate, [certificate]));
      const item = await CargoMessageSet.deserializeItem(rotation.serialize());

      expect(item).toBeInstanceOf(CertificateRotation);
      const rotationDeserialized = item as CertificateRotation;
      expect(
        rotationDeserialized.certificationPath.leafCertificate.isEqual(certificate),
      ).toBeTrue();
      expect(
        rotationDeserialized.certificationPath.certificateAuthorities[0].isEqual(certificate),
      ).toBeTrue();
    });

    test('An error should be thrown when non-RAMF message is found', async () => {
      const invalidItemSerialized = arrayBufferFrom('Not RAMF');

      await expect(CargoMessageSet.deserializeItem(invalidItemSerialized)).rejects.toThrow(
        /Value is not a valid Cargo Message Set item/,
      );
    });

    test('An error should be yielded when unsupported RAMF message is found', async () => {
      const innerCargo = new Cargo({ id: 'address' }, certificate, Buffer.from('hi'));
      const cargoSerialization = await innerCargo.serialize(privateKey);

      await expect(CargoMessageSet.deserializeItem(cargoSerialization)).rejects.toThrow(
        /Value is not a valid Cargo Message Set item/,
      );
    });
  });

  describe('batchMessagesSerialized', () => {
    const EXPIRY_DATE = new Date();

    test('Zero messages should result in zero batches', async () => {
      const messages = arrayToAsyncIterable([]);

      const batches = await asyncIterableToArray(CargoMessageSet.batchMessagesSerialized(messages));

      expect(batches).toHaveLength(0);
    });

    test('A single message should result in one batch', async () => {
      const messageSerialized = arrayBufferFrom('I am a parcel.');
      const messages = arrayToAsyncIterable([{ messageSerialized, expiryDate: EXPIRY_DATE }]);

      const batches = await asyncIterableToArray(CargoMessageSet.batchMessagesSerialized(messages));

      expect(batches).toHaveLength(1);
      const messageSet = CargoMessageSet.deserialize(batches[0].messageSerialized);
      expect(messageSet.messages).toEqual([messageSerialized]);
    });

    test('Multiple small messages should be put in the same batch', async () => {
      const messagesSerialized: readonly MessageWithExpiryDate[] = [
        { messageSerialized: arrayBufferFrom('I am a parcel.'), expiryDate: EXPIRY_DATE },
        { messageSerialized: arrayBufferFrom('And I am also a parcel.'), expiryDate: EXPIRY_DATE },
      ];
      const messages = arrayToAsyncIterable(messagesSerialized);

      const batches = await asyncIterableToArray(CargoMessageSet.batchMessagesSerialized(messages));

      expect(batches).toHaveLength(1);
      const messageSet = CargoMessageSet.deserialize(batches[0].messageSerialized);
      expect(messageSet.messages).toEqual(messagesSerialized.map((m) => m.messageSerialized));
    });

    test('Messages should be put into as few batches as possible', async () => {
      const octetsIn3Mib = 3145728;
      const messageSerialized = arrayBufferFrom('a'.repeat(octetsIn3Mib));
      const messages = arrayToAsyncIterable([
        { messageSerialized, expiryDate: EXPIRY_DATE },
        { messageSerialized, expiryDate: EXPIRY_DATE },
        { messageSerialized, expiryDate: EXPIRY_DATE },
      ]);

      const batches = await asyncIterableToArray(CargoMessageSet.batchMessagesSerialized(messages));

      expect(batches).toHaveLength(2);
      const messageSet1 = CargoMessageSet.deserialize(batches[0].messageSerialized);
      expect(messageSet1.messages).toEqual([messageSerialized, messageSerialized]);
      const messageSet2 = CargoMessageSet.deserialize(batches[1].messageSerialized);
      expect(messageSet2.messages).toEqual([messageSerialized]);
    });

    test('Messages exceeding the max per-message size should be refused', async () => {
      const messageSerialized = arrayBufferFrom('a'.repeat(CargoMessageSet.MAX_MESSAGE_LENGTH + 1));
      const messages = arrayToAsyncIterable([{ messageSerialized, expiryDate: EXPIRY_DATE }]);

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
      const messages = arrayToAsyncIterable([{ messageSerialized, expiryDate: EXPIRY_DATE }]);

      const batches = await asyncIterableToArray(CargoMessageSet.batchMessagesSerialized(messages));

      expect(batches).toHaveLength(1);
      expect(batches[0].messageSerialized.byteLength).toEqual(MAX_SDU_PLAINTEXT_LENGTH);
      const messageSet = CargoMessageSet.deserialize(batches[0].messageSerialized);
      expect(messageSet.messages).toEqual([messageSerialized]);
    });

    test('Messages collectively reaching max length should be placed together', async () => {
      const messageSerialized1 = arrayBufferFrom(
        'a'.repeat(CargoMessageSet.MAX_MESSAGE_LENGTH / 2 - 3),
      );
      const messageSerialized2 = arrayBufferFrom(
        'a'.repeat(CargoMessageSet.MAX_MESSAGE_LENGTH / 2 - 2),
      );
      const messages = arrayToAsyncIterable([
        { messageSerialized: messageSerialized1, expiryDate: EXPIRY_DATE },
        { messageSerialized: messageSerialized2, expiryDate: EXPIRY_DATE },
      ]);

      const batches = await asyncIterableToArray(CargoMessageSet.batchMessagesSerialized(messages));

      expect(batches).toHaveLength(1);
      expect(batches[0].messageSerialized.byteLength).toEqual(MAX_SDU_PLAINTEXT_LENGTH);
      const messageSet = CargoMessageSet.deserialize(batches[0].messageSerialized);
      expect(messageSet.messages).toEqual([messageSerialized1, messageSerialized2]);
    });

    test('Expiry date of batch should be that of its message with latest expiry', async () => {
      const octetsIn3Mib = 3145728;
      const messageSerialized = arrayBufferFrom('a'.repeat(octetsIn3Mib));
      const message1ExpiryDate = new Date(2017, 2, 1);
      const message2ExpiryDate = new Date(2017, 1, 2);
      const message3ExpiryDate = new Date(2017, 1, 3);
      const message4ExpiryDate = new Date(2017, 1, 4);
      const messages = arrayToAsyncIterable([
        { messageSerialized, expiryDate: message1ExpiryDate },
        { messageSerialized, expiryDate: message2ExpiryDate },
        { messageSerialized, expiryDate: message3ExpiryDate },
        { messageSerialized, expiryDate: message4ExpiryDate },
      ]);

      const batches = await asyncIterableToArray(CargoMessageSet.batchMessagesSerialized(messages));

      expect(batches).toHaveLength(2);
      expect(batches[0].expiryDate).toEqual(message1ExpiryDate);
      expect(batches[1].expiryDate).toEqual(message4ExpiryDate);
    });
  });

  describe('serialize', () => {
    test('An empty array should serialized as such', () => {
      const payload = new CargoMessageSet([]);

      const serialization = payload.serialize();

      const deserialization = derDeserialize(serialization);
      expect(deserialization).toBeInstanceOf(asn1js.Sequence);
      expect((deserialization as asn1js.Set).valueBlock.value).toHaveLength(0);
    });

    test('A one-item array should serialized as such', () => {
      const payload = new CargoMessageSet([STUB_MESSAGE]);

      const serialization = payload.serialize();

      const deserialization = derDeserialize(serialization);
      expect(deserialization).toBeInstanceOf(asn1js.Sequence);

      expect((deserialization as asn1js.Set).valueBlock.value).toHaveLength(1);
      const stubMessageAsn1 = (deserialization as asn1js.Sequence).valueBlock.value[0];
      expect(stubMessageAsn1).toBeInstanceOf(asn1js.OctetString);
      expectArrayBuffersToEqual(
        (stubMessageAsn1 as asn1js.OctetString).valueBlock.valueHex,
        STUB_MESSAGE,
      );
    });

    test('A multi-item array should serialized as such', () => {
      const stubMessages: readonly ArrayBuffer[] = [STUB_MESSAGE, arrayBufferFrom('bye')];
      const payload = new CargoMessageSet(stubMessages);

      const serialization = payload.serialize();

      const deserialization = derDeserialize(serialization);
      expect(deserialization).toBeInstanceOf(asn1js.Sequence);

      expect((deserialization as asn1js.Sequence).valueBlock.value).toHaveLength(
        stubMessages.length,
      );
      for (let index = 0; index < stubMessages.length; index++) {
        const messageAsn1 = (deserialization as asn1js.Sequence).valueBlock.value[index];
        expect(messageAsn1).toBeInstanceOf(asn1js.OctetString);
        expectArrayBuffersToEqual(
          (messageAsn1 as asn1js.OctetString).valueBlock.valueHex,
          stubMessages[index],
        );
      }
    });
  });
});
