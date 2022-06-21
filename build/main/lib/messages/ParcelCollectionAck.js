"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ParcelCollectionAck = void 0;
const asn1js_1 = require("asn1js");
const util_1 = require("util");
const asn1_1 = require("../asn1");
const formatSignature_1 = require("./formatSignature");
const InvalidMessageError_1 = __importDefault(require("./InvalidMessageError"));
class ParcelCollectionAck {
    constructor(senderEndpointPrivateAddress, recipientEndpointAddress, parcelId) {
        this.senderEndpointPrivateAddress = senderEndpointPrivateAddress;
        this.recipientEndpointAddress = recipientEndpointAddress;
        this.parcelId = parcelId;
    }
    static deserialize(pcaSerialized) {
        const formatSignature = Buffer.from(pcaSerialized.slice(0, ParcelCollectionAck.FORMAT_SIGNATURE.byteLength));
        if (!formatSignature.equals(ParcelCollectionAck.FORMAT_SIGNATURE)) {
            throw new InvalidMessageError_1.default('Format signature should be that of a PCA');
        }
        const pcaSequenceSerialized = pcaSerialized.slice(10);
        const result = (0, asn1js_1.verifySchema)(pcaSequenceSerialized, ParcelCollectionAck.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError_1.default('PCA did not meet required structure');
        }
        const textDecoder = new util_1.TextDecoder();
        const pcaBlock = result.result.ParcelCollectionAck;
        return new ParcelCollectionAck(textDecoder.decode(pcaBlock.senderEndpointPrivateAddress.valueBlock.valueHex), textDecoder.decode(pcaBlock.recipientEndpointAddress.valueBlock.valueHex), textDecoder.decode(pcaBlock.parcelId.valueBlock.valueHex));
    }
    serialize() {
        const ackSerialized = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.VisibleString({ value: this.senderEndpointPrivateAddress }), new asn1js_1.VisibleString({ value: this.recipientEndpointAddress }), new asn1js_1.VisibleString({ value: this.parcelId })).toBER();
        const serialization = new ArrayBuffer(ParcelCollectionAck.FORMAT_SIGNATURE.byteLength + ackSerialized.byteLength);
        const serializationView = new Uint8Array(serialization);
        serializationView.set(ParcelCollectionAck.FORMAT_SIGNATURE, 0);
        serializationView.set(new Uint8Array(ackSerialized), ParcelCollectionAck.FORMAT_SIGNATURE.byteLength);
        return serialization;
    }
}
exports.ParcelCollectionAck = ParcelCollectionAck;
ParcelCollectionAck.FORMAT_SIGNATURE = (0, formatSignature_1.generateFormatSignature)(0x51, 0);
ParcelCollectionAck.SCHEMA = (0, asn1_1.makeHeterogeneousSequenceSchema)('ParcelCollectionAck', [
    new asn1js_1.Primitive({ name: 'senderEndpointPrivateAddress' }),
    new asn1js_1.Primitive({ name: 'recipientEndpointAddress' }),
    new asn1js_1.Primitive({ name: 'parcelId' }),
]);
//# sourceMappingURL=ParcelCollectionAck.js.map