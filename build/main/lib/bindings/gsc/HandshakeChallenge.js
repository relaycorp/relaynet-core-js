"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.HandshakeChallenge = void 0;
const asn1js_1 = require("asn1js");
const asn1_1 = require("../../asn1");
const InvalidMessageError_1 = __importDefault(require("../../messages/InvalidMessageError"));
class HandshakeChallenge {
    constructor(nonce) {
        this.nonce = nonce;
    }
    static deserialize(serialization) {
        const result = (0, asn1js_1.verifySchema)(serialization, HandshakeChallenge.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError_1.default('Handshake challenge is malformed');
        }
        const challengeASN1 = result.result.HandshakeChallenge;
        const nonce = challengeASN1.nonce.valueBlock.valueHex;
        return new HandshakeChallenge(nonce);
    }
    serialize() {
        return (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: this.nonce })).toBER();
    }
}
exports.HandshakeChallenge = HandshakeChallenge;
HandshakeChallenge.SCHEMA = (0, asn1_1.makeHeterogeneousSequenceSchema)('HandshakeChallenge', [
    new asn1js_1.Primitive({ name: 'nonce' }),
]);
//# sourceMappingURL=HandshakeChallenge.js.map