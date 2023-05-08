import * as asn1js from 'asn1js';

import { arrayBufferFrom } from '../_test_utils';
import { derDeserialize } from '../crypto/_utils';
import { InvalidMessageError } from './InvalidMessageError';
import { ParcelCollectionAck } from './ParcelCollectionAck';

describe('ParcelCollectionAck', () => {
  const SENDER_ENDPOINT_ID = '0deadbeef';
  const RECIPIENT_ENDPOINT_INTERNET_ADDRESS = 'example.com';
  const PARCEL_ID = 'the-parcel-id';

  describe('serialize', () => {
    test('Serialization should start with format signature', () => {
      const pca = new ParcelCollectionAck(
        SENDER_ENDPOINT_ID,
        RECIPIENT_ENDPOINT_INTERNET_ADDRESS,
        PARCEL_ID,
      );

      const pcaSerialized = pca.serialize();

      const expectedFormatSignature = Buffer.concat([
        Buffer.from('Awala'),
        Buffer.from([0x51, 0x00]),
      ]);
      expect(Buffer.from(pcaSerialized).slice(0, 7)).toEqual(expectedFormatSignature);
    });

    test('An ACK should be serialized as a 3-item sequence', () => {
      const pca = new ParcelCollectionAck(
        SENDER_ENDPOINT_ID,
        RECIPIENT_ENDPOINT_INTERNET_ADDRESS,
        PARCEL_ID,
      );

      const pcaBlock = parsePCA(pca.serialize());

      expect(pcaBlock).toBeInstanceOf(asn1js.Sequence);
      const pcaSequenceBlock = pcaBlock as asn1js.Sequence;
      const pcaSequenceItems = pcaSequenceBlock.valueBlock.value;
      expect(pcaSequenceItems).toHaveLength(3);
      expect((pcaSequenceItems[0] as asn1js.Primitive).valueBlock.valueHex).toEqual(
        arrayBufferFrom(SENDER_ENDPOINT_ID),
      );
      expect((pcaSequenceItems[1] as asn1js.Primitive).valueBlock.valueHex).toEqual(
        arrayBufferFrom(RECIPIENT_ENDPOINT_INTERNET_ADDRESS),
      );
      expect((pcaSequenceItems[2] as asn1js.Primitive).valueBlock.valueHex).toEqual(
        arrayBufferFrom(PARCEL_ID),
      );
    });

    function skipFormatSignatureFromSerialization(pcaSerialized: ArrayBuffer): ArrayBuffer {
      return pcaSerialized.slice(7);
    }

    function parsePCA(pcaSerialized: ArrayBuffer): asn1js.Sequence {
      const derSequenceSerialized = skipFormatSignatureFromSerialization(pcaSerialized);
      return derDeserialize(derSequenceSerialized) as asn1js.Sequence;
    }
  });

  describe('deserialize', () => {
    test('Serialization should start with format signature', () => {
      const invalidSerialization = arrayBufferFrom('RelaynetA0');

      expect(() => ParcelCollectionAck.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Format signature should be that of a PCA',
      );
    });

    test('ACK should be refused if it has fewer than 3 items', () => {
      // Pass an ACK with 2 VisibleStrings instead of 3
      const invalidSerialization = arrayBufferFrom([
        ...ParcelCollectionAck.FORMAT_SIGNATURE,
        ...Buffer.from(
          new asn1js.Sequence({
            value: [new asn1js.VisibleString(), new asn1js.VisibleString()],
          } as any).toBER(false),
        ),
      ]);

      expect(() => ParcelCollectionAck.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'PCA did not meet required structure',
      );
    });

    test('Each ACK should be a three-item sequence of VisibleStrings', () => {
      const invalidSerialization = arrayBufferFrom([
        ...ParcelCollectionAck.FORMAT_SIGNATURE,
        ...Buffer.from(
          new asn1js.Sequence({
            value: [
              new asn1js.VisibleString(),
              new asn1js.Integer({ value: 42 }),
              new asn1js.VisibleString(),
            ],
          } as any).toBER(false),
        ),
      ]);

      expect(() => ParcelCollectionAck.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'PCA did not meet required structure',
      );
    });

    test('A new instance should be returned if serialization is valid', () => {
      const pca = new ParcelCollectionAck(
        SENDER_ENDPOINT_ID,
        RECIPIENT_ENDPOINT_INTERNET_ADDRESS,
        PARCEL_ID,
      );

      const pcaDeserialized = ParcelCollectionAck.deserialize(pca.serialize());

      expect(pcaDeserialized.senderEndpointId).toEqual(SENDER_ENDPOINT_ID);
      expect(pcaDeserialized.recipientEndpointId).toEqual(RECIPIENT_ENDPOINT_INTERNET_ADDRESS);
      expect(pcaDeserialized.parcelId).toEqual(PARCEL_ID);
    });
  });
});
