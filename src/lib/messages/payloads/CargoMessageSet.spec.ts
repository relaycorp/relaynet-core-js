/* tslint:disable:no-let no-object-mutation */
import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';

import {
  convertAsyncIteratorToArray,
  expectBuffersToEqual,
  generateStubCert,
} from '../../_test_utils';
import { deserializeDer } from '../../crypto_wrappers/_utils';
import { generateRSAKeyPair } from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import Cargo from '../Cargo';
import InvalidMessageError from '../InvalidMessageError';
import Parcel from '../Parcel';
import CargoMessageSet from './CargoMessageSet';

const STUB_MESSAGE = Buffer.from('hiya');

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
      asn1Set.valueBlock.value = [new asn1js.BitString({ valueHex: bufferToArray(STUB_MESSAGE) })];
      const serialization = asn1Set.toBER(false);

      const cargoMessages = CargoMessageSet.deserialize(serialization);
      expect(cargoMessages.messages).toEqual(new Set([STUB_MESSAGE]));
    });

    test('A multi-item set should be accepted', () => {
      const messages: readonly Buffer[] = [STUB_MESSAGE, Buffer.from('another message')];
      const asn1Set = new asn1js.Set();
      asn1Set.valueBlock.value = messages.map(
        m => new asn1js.BitString({ valueHex: bufferToArray(m) }),
      );
      const serialization = asn1Set.toBER(false);

      const cargoMessages = CargoMessageSet.deserialize(serialization);
      expect(cargoMessages.messages).toEqual(new Set(messages));
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
      expectBuffersToEqual(
        (stubMessageAsn1 as asn1js.BitString).valueBlock.valueHex,
        bufferToArray(STUB_MESSAGE),
      );
    });

    test('A multi-item set should serialized as such', () => {
      const stubMessages: readonly Buffer[] = [STUB_MESSAGE, Buffer.from('bye')];
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
          bufferToArray(stubMessages[index]),
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
      const parcelSerialization = Buffer.from(await parcel.serialize(privateKey));
      const cargoMessageSet = new CargoMessageSet(new Set([parcelSerialization]));

      const messages = await convertAsyncIteratorToArray(cargoMessageSet.deserializeMessages());

      expect(messages).toHaveLength(1);
      expect(messages[0]).toBeInstanceOf(Parcel);
      expect(messages[0]).toHaveProperty('recipientAddress', parcel.recipientAddress);
    });

    test('An error should be thrown when non-RAMF messages are found', async () => {
      const cargoMessageSet = new CargoMessageSet(new Set([Buffer.from('Not RAMF')]));

      await expect(
        convertAsyncIteratorToArray(cargoMessageSet.deserializeMessages()),
      ).rejects.toMatchObject<Partial<InvalidMessageError>>({
        message: expect.stringMatching(
          /^Invalid message found: Serialization starts with invalid RAMF format signature/,
        ),
      });
    });

    test('An error should be thrown when unsupported RAMF messages are found', async () => {
      const innerCargo = new Cargo('address', certificate, Buffer.from('hi'));
      const cargoSerialization = Buffer.from(await innerCargo.serialize(privateKey));
      const cargoMessageSet = new CargoMessageSet(new Set([cargoSerialization]));

      await expect(
        convertAsyncIteratorToArray(cargoMessageSet.deserializeMessages()),
      ).rejects.toMatchObject<Partial<InvalidMessageError>>({
        message: expect.stringMatching(/^Invalid message found: Expected concrete message type/),
      });
    });

    test('An empty set should result in no yielded values', async () => {
      const cargoMessageSet = new CargoMessageSet(new Set([]));

      await expect(
        convertAsyncIteratorToArray(cargoMessageSet.deserializeMessages()),
      ).resolves.toEqual([]);
    });
  });
});
