"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const asn1js_1 = require("asn1js");
const _test_utils_1 = require("../../_test_utils");
const _utils_1 = require("../../crypto_wrappers/_utils");
const InvalidMessageError_1 = __importDefault(require("../../messages/InvalidMessageError"));
const HandshakeChallenge_1 = require("./HandshakeChallenge");
const NONCE = (0, _test_utils_1.arrayBufferFrom)('The nonce');
describe('serialize', () => {
    test('Nonce should be sole item in ASN.1 SEQUENCE', () => {
        const challenge = new HandshakeChallenge_1.HandshakeChallenge(NONCE);
        const serialization = challenge.serialize();
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        expect(sequence).toBeInstanceOf(asn1js_1.Sequence);
        (0, _test_utils_1.expectArrayBuffersToEqual)(NONCE, sequence.valueBlock.value[0].valueBlock.valueHex);
    });
});
describe('deserialized', () => {
    test('Invalid serialization should be refused', () => {
        const invalidSerialization = (0, _test_utils_1.arrayBufferFrom)('I am a "challenge" :wink: :wink:');
        expect(() => HandshakeChallenge_1.HandshakeChallenge.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Handshake challenge is malformed');
    });
    test('Valid serialization should be accepted', () => {
        const challenge = new HandshakeChallenge_1.HandshakeChallenge(NONCE);
        const serialization = challenge.serialize();
        const challengeDeserialized = HandshakeChallenge_1.HandshakeChallenge.deserialize(serialization);
        (0, _test_utils_1.expectArrayBuffersToEqual)(NONCE, challengeDeserialized.nonce);
    });
});
//# sourceMappingURL=HandshakeChallenge.spec.js.map