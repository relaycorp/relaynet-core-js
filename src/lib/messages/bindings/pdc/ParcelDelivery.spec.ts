import { Integer, Primitive, Sequence } from 'asn1js';

import { arrayBufferFrom, expectBuffersToEqual } from '../../../_test_utils';
import { derSerializeHeterogeneousSequence } from '../../../asn1';
import { derDeserialize } from '../../../crypto_wrappers/_utils';
import InvalidMessageError from '../../InvalidMessageError';
import { ParcelDelivery } from './ParcelDelivery';

const DELIVERY_ID = 'the id';
const PARCEL_SERIALIZED = arrayBufferFrom('This appears to be a parcel');

describe('serialize', () => {
  test('Delivery id should be serialized', () => {
    const delivery = new ParcelDelivery(DELIVERY_ID, PARCEL_SERIALIZED);

    const serialization = delivery.serialize();

    const sequence = derDeserialize(serialization);
    expect(sequence).toBeInstanceOf(Sequence);
    const deliveryIdASN1 = (sequence as Sequence).valueBlock.value[0];
    expect(deliveryIdASN1).toBeInstanceOf(Primitive);
    expectBuffersToEqual(
      (deliveryIdASN1 as Primitive).valueBlock.valueHex,
      arrayBufferFrom(DELIVERY_ID),
    );
  });

  test('Parcel should be serialized', () => {
    const delivery = new ParcelDelivery(DELIVERY_ID, PARCEL_SERIALIZED);

    const serialization = delivery.serialize();

    const sequence = derDeserialize(serialization);
    expect(sequence).toBeInstanceOf(Sequence);
    const parcelSerializedASN1 = (sequence as Sequence).valueBlock.value[1];
    expect(parcelSerializedASN1).toBeInstanceOf(Primitive);
    expectBuffersToEqual(
      (parcelSerializedASN1 as Primitive).valueBlock.valueHex,
      PARCEL_SERIALIZED,
    );
  });
});

describe('deserialize', () => {
  test('Serialization should be a DER sequence', () => {
    const invalidSerialization = new Integer({ value: 42 }).toBER();

    expect(() => ParcelDelivery.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      'Parcel delivery is malformed',
    );
  });

  test('Sequence should have at lease two items', () => {
    const invalidSerialization = derSerializeHeterogeneousSequence(new Integer({ value: 42 }));

    expect(() => ParcelDelivery.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      'Parcel delivery is malformed',
    );
  });

  test('Valid deliveries should be accepted', () => {
    const delivery = new ParcelDelivery(DELIVERY_ID, PARCEL_SERIALIZED);
    const serialization = delivery.serialize();

    const deserialization = ParcelDelivery.deserialize(serialization);

    expect(deserialization.deliveryId).toEqual(DELIVERY_ID);
    expectBuffersToEqual(deserialization.parcelSerialized, PARCEL_SERIALIZED);
  });
});
