import { OctetString, Primitive, verifySchema, VisibleString } from 'asn1js';
import { TextDecoder } from 'util';

import { derSerializeHeterogeneousSequence, makeHeterogeneousSequenceSchema } from '../../../asn1';
import InvalidMessageError from '../../InvalidMessageError';

export class ParcelDelivery {
  public static deserialize(serialization: ArrayBuffer): ParcelDelivery {
    const result = verifySchema(serialization, ParcelDelivery.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Parcel delivery is malformed');
    }

    const textDecoder = new TextDecoder();
    const deliveryASN1 = result.result.ParcelDelivery;
    return new ParcelDelivery(
      textDecoder.decode(deliveryASN1.deliveryId.valueBlock.valueHex),
      deliveryASN1.parcelSerialized.valueBlock.valueHex,
    );
  }

  private static readonly SCHEMA = makeHeterogeneousSequenceSchema('ParcelDelivery', [
    new Primitive({ name: 'deliveryId' }),
    new Primitive({ name: 'parcelSerialized' }),
  ]);

  constructor(public deliveryId: string, public parcelSerialized: ArrayBuffer) {}

  public serialize(): ArrayBuffer {
    return derSerializeHeterogeneousSequence(
      new VisibleString({ value: this.deliveryId }),
      new OctetString({ valueHex: this.parcelSerialized }),
    );
  }
}
