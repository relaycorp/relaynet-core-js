import { OctetString, Primitive, verifySchema, VisibleString } from 'asn1js';
import { TextDecoder } from 'util';
import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../../asn1';
import InvalidMessageError from '../../messages/InvalidMessageError';
export class ParcelDelivery {
    deliveryId;
    parcelSerialized;
    static deserialize(serialization) {
        const result = verifySchema(serialization, ParcelDelivery.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError('Parcel delivery is malformed');
        }
        const textDecoder = new TextDecoder();
        const deliveryASN1 = result.result.ParcelDelivery;
        return new ParcelDelivery(textDecoder.decode(deliveryASN1.deliveryId.valueBlock.valueHex), deliveryASN1.parcelSerialized.valueBlock.valueHex);
    }
    static SCHEMA = makeHeterogeneousSequenceSchema('ParcelDelivery', [
        new Primitive({ name: 'deliveryId' }),
        new Primitive({ name: 'parcelSerialized' }),
    ]);
    constructor(deliveryId, parcelSerialized) {
        this.deliveryId = deliveryId;
        this.parcelSerialized = parcelSerialized;
    }
    serialize() {
        return makeImplicitlyTaggedSequence(new VisibleString({ value: this.deliveryId }), new OctetString({ valueHex: this.parcelSerialized })).toBER();
    }
}
//# sourceMappingURL=ParcelDelivery.js.map