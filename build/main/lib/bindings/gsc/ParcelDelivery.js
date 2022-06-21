"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ParcelDelivery = void 0;
const asn1js_1 = require("asn1js");
const util_1 = require("util");
const asn1_1 = require("../../asn1");
const InvalidMessageError_1 = __importDefault(require("../../messages/InvalidMessageError"));
class ParcelDelivery {
    constructor(deliveryId, parcelSerialized) {
        this.deliveryId = deliveryId;
        this.parcelSerialized = parcelSerialized;
    }
    static deserialize(serialization) {
        const result = (0, asn1js_1.verifySchema)(serialization, ParcelDelivery.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError_1.default('Parcel delivery is malformed');
        }
        const textDecoder = new util_1.TextDecoder();
        const deliveryASN1 = result.result.ParcelDelivery;
        return new ParcelDelivery(textDecoder.decode(deliveryASN1.deliveryId.valueBlock.valueHex), deliveryASN1.parcelSerialized.valueBlock.valueHex);
    }
    serialize() {
        return (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.VisibleString({ value: this.deliveryId }), new asn1js_1.OctetString({ valueHex: this.parcelSerialized })).toBER();
    }
}
exports.ParcelDelivery = ParcelDelivery;
ParcelDelivery.SCHEMA = (0, asn1_1.makeHeterogeneousSequenceSchema)('ParcelDelivery', [
    new asn1js_1.Primitive({ name: 'deliveryId' }),
    new asn1js_1.Primitive({ name: 'parcelSerialized' }),
]);
//# sourceMappingURL=ParcelDelivery.js.map