import * as asn1js from 'asn1js';

import { arrayBufferFrom } from '../_test_utils';
import { derDeserialize } from '../crypto_wrappers/_utils';
import InvalidMessageError from './InvalidMessageError';
import { ParcelCollectionAck, ParcelCollectionAckSet } from './ParcelCollectionAck';

describe('ParcelCollectionAck', () => {
  const ACK: ParcelCollectionAck = {
    parcelId: 'the-parcel-id',
    recipientEndpointAddress: 'https://example.com',
    senderEndpointPrivateAddress: '0deadbeef',
  };

  describe('serialize', () => {
    test('Serialization should start with format signature', () => {
      const ackSet = new ParcelCollectionAckSet(new Set([ACK]));

      const ackSetSerialized = ackSet.serialize();

      const expectedFormatSignature = Buffer.concat([
        Buffer.from('Relaynet'),
        Buffer.from([0x51, 0x00]),
      ]);
      expect(Buffer.from(ackSetSerialized).slice(0, 10)).toEqual(expectedFormatSignature);
    });

    test('ACKs should be encoded as a DER SET', () => {
      const ackSet = new ParcelCollectionAckSet(new Set([ACK]));

      const derSetSerialized = skipFormatSignatureFromSerialization(ackSet.serialize());

      expect(derDeserialize(derSetSerialized)).toBeInstanceOf(asn1js.Set);
    });

    test('ACKs may be empty', () => {
      const ackSet = new ParcelCollectionAckSet(new Set([]));

      const derSet = parseAckSet(ackSet.serialize());

      expect(derSet.valueBlock.value).toHaveLength(0);
    });

    test('An ACK should be a 3-item sequence', () => {
      const ackSet = new ParcelCollectionAckSet(new Set([ACK]));

      const derSet = parseAckSet(ackSet.serialize());

      const ack = derSet.valueBlock.value[0];
      expect(ack).toBeInstanceOf(asn1js.Sequence);
      expect((ack as asn1js.Sequence).valueBlock.value).toHaveLength(3);
    });

    test('First item in ACK set should be private address of sender endpoint', () => {
      const ackSet = new ParcelCollectionAckSet(new Set([ACK]));

      const derSet = parseAckSet(ackSet.serialize());

      const ack = derSet.valueBlock.value[0] as asn1js.Sequence;
      const addressBlock = ack.valueBlock.value[0] as asn1js.VisibleString;
      expect(addressBlock.valueBlock.value).toEqual(ACK.senderEndpointPrivateAddress);
    });

    test('Second item in ACK set should be address of recipient endpoint', () => {
      const ackSet = new ParcelCollectionAckSet(new Set([ACK]));

      const derSet = parseAckSet(ackSet.serialize());

      const ack = derSet.valueBlock.value[0] as asn1js.Sequence;
      const addressBlock = ack.valueBlock.value[1] as asn1js.VisibleString;
      expect(addressBlock.valueBlock.value).toEqual(ACK.recipientEndpointAddress);
    });

    test('Third item in ACK set should be parcel id', () => {
      const ackSet = new ParcelCollectionAckSet(new Set([ACK]));

      const derSet = parseAckSet(ackSet.serialize());

      const ack = derSet.valueBlock.value[0] as asn1js.Sequence;
      const parcelIdBlock = ack.valueBlock.value[2] as asn1js.VisibleString;
      expect(parcelIdBlock.valueBlock.value).toEqual(ACK.parcelId);
    });

    function skipFormatSignatureFromSerialization(ackSetSerialized: ArrayBuffer): ArrayBuffer {
      return ackSetSerialized.slice(10);
    }

    function parseAckSet(ackSetSerialized: ArrayBuffer): asn1js.Set {
      const derSetSerialized = skipFormatSignatureFromSerialization(ackSetSerialized);

      return derDeserialize(derSetSerialized) as asn1js.Set;
    }
  });

  describe('deserialize', () => {
    test('Serialization should start with format signature', () => {
      const invalidSerialization = arrayBufferFrom('RelaynetA0');

      expect(() => ParcelCollectionAckSet.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Format signature should be that of a PCA set',
      );
    });

    test('ACKs should be encoded as a DER SET', () => {
      // Pass an ASN.1 NULL instead of a SET
      const invalidSerialization = arrayBufferFrom([
        ...ParcelCollectionAckSet.FORMAT_SIGNATURE,
        ...Buffer.from(new asn1js.Null().toBER(false)),
      ]);

      expect(() => ParcelCollectionAckSet.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'PCA set did not meet required structure',
      );
    });

    test('ACK should be refused if it has fewer than 3 items', () => {
      // Pass an ACK with 2 VisibleStrings instead of 3
      const invalidSerialization = arrayBufferFrom([
        ...ParcelCollectionAckSet.FORMAT_SIGNATURE,
        ...Buffer.from(
          new asn1js.Set({
            value: [
              new asn1js.Sequence({
                value: [new asn1js.VisibleString(), new asn1js.VisibleString()],
              } as any),
            ],
          } as any).toBER(false),
        ),
      ]);

      expect(() => ParcelCollectionAckSet.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'PCA set did not meet required structure',
      );
    });

    test('Each ACK should be a three-item sequence of VisibleStrings', () => {
      const invalidSerialization = arrayBufferFrom([
        ...ParcelCollectionAckSet.FORMAT_SIGNATURE,
        ...Buffer.from(
          new asn1js.Set({
            value: [
              new asn1js.Sequence({
                value: [
                  new asn1js.VisibleString(),
                  new asn1js.Integer({ value: 42 }),
                  new asn1js.VisibleString(),
                ],
              } as any),
            ],
          } as any).toBER(false),
        ),
      ]);

      expect(() => ParcelCollectionAckSet.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'PCA set did not meet required structure',
      );
    });

    test('A new instance should be returned if serialization is valid', () => {
      const invalidSerialization = arrayBufferFrom([
        ...ParcelCollectionAckSet.FORMAT_SIGNATURE,
        ...Buffer.from(
          new asn1js.Set({
            value: [
              new asn1js.Sequence({
                value: [
                  new asn1js.VisibleString({ value: ACK.senderEndpointPrivateAddress }),
                  new asn1js.VisibleString({ value: ACK.recipientEndpointAddress }),
                  new asn1js.VisibleString({ value: ACK.parcelId }),
                ],
              } as any),
            ],
          } as any).toBER(false),
        ),
      ]);

      const pcaSet = ParcelCollectionAckSet.deserialize(invalidSerialization);
      expect(pcaSet.acks).toHaveProperty('size', 1);
      expect(Array.from(pcaSet.acks)[0]).toEqual(ACK);
    });

    test('PCA set may be empty', () => {
      const invalidSerialization = arrayBufferFrom([
        ...ParcelCollectionAckSet.FORMAT_SIGNATURE,
        ...Buffer.from(new asn1js.Set({ value: [] } as any).toBER(false)),
      ]);

      const pcaSet = ParcelCollectionAckSet.deserialize(invalidSerialization);
      expect(pcaSet.acks).toHaveProperty('size', 0);
    });
  });
});
