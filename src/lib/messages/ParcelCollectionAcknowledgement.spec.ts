import * as asn1js from 'asn1js';

import { derDeserialize } from '../crypto_wrappers/_utils';
import {
  ParcelCollectionAcknowledgement,
  ParcelCollectionAcknowledgementSet,
} from './ParcelCollectionAcknowledgement';

describe('ParcelCollectionAcknowledgement', () => {
  describe('serialize', () => {
    const ACK: ParcelCollectionAcknowledgement = {
      parcelId: 'the-parcel-id',
      recipientEndpointAddress: 'https://example.com',
      senderEndpointPrivateAddress: '0deadbeef',
    };

    test('Serialization should start with format signature', () => {
      const ackSet = new ParcelCollectionAcknowledgementSet(new Set([ACK]));

      const ackSetSerialized = ackSet.serialize();

      const expectedFormatSignature = Buffer.concat([
        Buffer.from('Relaynet'),
        Buffer.from([0x51, 0x00]),
      ]);
      expect(Buffer.from(ackSetSerialized).slice(0, 10)).toEqual(expectedFormatSignature);
    });

    test('ACKs should be encoded as a DER SET', () => {
      const ackSet = new ParcelCollectionAcknowledgementSet(new Set([ACK]));

      const derSetSerialized = skipFormatSignatureFromSerialization(ackSet.serialize());

      expect(derDeserialize(derSetSerialized)).toBeInstanceOf(asn1js.Set);
    });

    test('ACKs may be empty', () => {
      const ackSet = new ParcelCollectionAcknowledgementSet(new Set([]));

      const derSet = parseAckSet(ackSet.serialize());

      expect(derSet.valueBlock.value).toHaveLength(0);
    });

    test('An ACK should be a 3-item sequence', () => {
      const ackSet = new ParcelCollectionAcknowledgementSet(new Set([ACK]));

      const derSet = parseAckSet(ackSet.serialize());

      const ack = derSet.valueBlock.value[0];
      expect(ack).toBeInstanceOf(asn1js.Sequence);
      expect((ack as asn1js.Sequence).valueBlock.value).toHaveLength(3);
    });

    test('First item in ACK set should be private address of sender endpoint', () => {
      const ackSet = new ParcelCollectionAcknowledgementSet(new Set([ACK]));

      const derSet = parseAckSet(ackSet.serialize());

      const ack = derSet.valueBlock.value[0] as asn1js.Sequence;
      const addressBlock = ack.valueBlock.value[0] as asn1js.VisibleString;
      expect(addressBlock.valueBlock.value).toEqual(ACK.senderEndpointPrivateAddress);
    });

    test('Second item in ACK set should be address of recipient endpoint', () => {
      const ackSet = new ParcelCollectionAcknowledgementSet(new Set([ACK]));

      const derSet = parseAckSet(ackSet.serialize());

      const ack = derSet.valueBlock.value[0] as asn1js.Sequence;
      const addressBlock = ack.valueBlock.value[1] as asn1js.VisibleString;
      expect(addressBlock.valueBlock.value).toEqual(ACK.recipientEndpointAddress);
    });

    test('Third item in ACK set should be parcel id', () => {
      const ackSet = new ParcelCollectionAcknowledgementSet(new Set([ACK]));

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
    test.todo('Serialization should start with format signature');

    test.todo('ACKs should be encoded as a DER SET');

    test.todo('Each ACK should be a two-item sequence of VisibleStrings');
  });
});
