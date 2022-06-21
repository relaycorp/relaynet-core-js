"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.HandshakeResponse = void 0;
const asn1js_1 = require("asn1js");
const asn1_1 = require("../../asn1");
const InvalidMessageError_1 = __importDefault(require("../../messages/InvalidMessageError"));
class HandshakeResponse {
    constructor(nonceSignatures) {
        this.nonceSignatures = nonceSignatures;
    }
    static deserialize(serialization) {
        const result = (0, asn1js_1.verifySchema)(serialization, HandshakeResponse.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError_1.default('Handshake response is malformed');
        }
        const responseASN1 = result.result.HandshakeResponse;
        const signatures = responseASN1.nonceSignatures.valueBlock.value.map((s) => s.valueBlock.valueHex);
        return new HandshakeResponse(signatures);
    }
    serialize() {
        const asn1NonceSignatures = this.nonceSignatures.map((s) => new asn1js_1.OctetString({ valueHex: s }));
        const nonceSignaturesASN1 = new asn1js_1.Constructed({ value: asn1NonceSignatures });
        return (0, asn1_1.makeImplicitlyTaggedSequence)(nonceSignaturesASN1).toBER();
    }
}
exports.HandshakeResponse = HandshakeResponse;
HandshakeResponse.SCHEMA = (0, asn1_1.makeHeterogeneousSequenceSchema)('HandshakeResponse', [
    new asn1js_1.Constructed({
        name: 'nonceSignatures',
        value: new asn1js_1.Repeated({
            name: 'nonceSignature',
            value: new asn1js_1.OctetString({ name: 'signature' }),
        }),
    }),
]);
//# sourceMappingURL=HandshakeResponse.js.map