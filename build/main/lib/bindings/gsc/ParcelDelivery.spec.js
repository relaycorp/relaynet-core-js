"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const asn1js_1 = require("asn1js");
const _test_utils_1 = require("../../_test_utils");
const asn1_1 = require("../../asn1");
const _utils_1 = require("../../crypto_wrappers/_utils");
const InvalidMessageError_1 = __importDefault(require("../../messages/InvalidMessageError"));
const ParcelDelivery_1 = require("./ParcelDelivery");
const DELIVERY_ID = 'the id';
const PARCEL_SERIALIZED = (0, _test_utils_1.arrayBufferFrom)('This appears to be a parcel');
describe('serialize', () => {
    test('Delivery id should be serialized', () => {
        const delivery = new ParcelDelivery_1.ParcelDelivery(DELIVERY_ID, PARCEL_SERIALIZED);
        const serialization = delivery.serialize();
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        expect(sequence).toBeInstanceOf(asn1js_1.Sequence);
        const deliveryIdASN1 = sequence.valueBlock.value[0];
        expect(deliveryIdASN1).toBeInstanceOf(asn1js_1.Primitive);
        (0, _test_utils_1.expectArrayBuffersToEqual)(deliveryIdASN1.valueBlock.valueHex, (0, _test_utils_1.arrayBufferFrom)(DELIVERY_ID));
    });
    test('Parcel should be serialized', () => {
        const delivery = new ParcelDelivery_1.ParcelDelivery(DELIVERY_ID, PARCEL_SERIALIZED);
        const serialization = delivery.serialize();
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        expect(sequence).toBeInstanceOf(asn1js_1.Sequence);
        const parcelSerializedASN1 = sequence.valueBlock.value[1];
        expect(parcelSerializedASN1).toBeInstanceOf(asn1js_1.Primitive);
        (0, _test_utils_1.expectArrayBuffersToEqual)(parcelSerializedASN1.valueBlock.valueHex, PARCEL_SERIALIZED);
    });
});
describe('deserialize', () => {
    test('Serialization should be a DER sequence', () => {
        const invalidSerialization = new asn1js_1.Integer({ value: 42 }).toBER();
        expect(() => ParcelDelivery_1.ParcelDelivery.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Parcel delivery is malformed');
    });
    test('Sequence should have at lease two items', () => {
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.Integer({ value: 42 })).toBER();
        expect(() => ParcelDelivery_1.ParcelDelivery.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Parcel delivery is malformed');
    });
    test('Valid deliveries should be accepted', () => {
        const delivery = new ParcelDelivery_1.ParcelDelivery(DELIVERY_ID, PARCEL_SERIALIZED);
        const serialization = delivery.serialize();
        const deserialization = ParcelDelivery_1.ParcelDelivery.deserialize(serialization);
        expect(deserialization.deliveryId).toEqual(DELIVERY_ID);
        (0, _test_utils_1.expectArrayBuffersToEqual)(deserialization.parcelSerialized, PARCEL_SERIALIZED);
    });
});
//# sourceMappingURL=ParcelDelivery.spec.js.map