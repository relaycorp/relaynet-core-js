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
const HandshakeResponse_1 = require("./HandshakeResponse");
const SIGNATURE1 = (0, _test_utils_1.arrayBufferFrom)('Signature 1');
const SIGNATURE2 = (0, _test_utils_1.arrayBufferFrom)('Signature 2');
describe('serialize', () => {
    test('Output should be an ASN.1 SEQUENCE', () => {
        const response = new HandshakeResponse_1.HandshakeResponse([]);
        const serialization = response.serialize();
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        expect(sequence).toBeInstanceOf(asn1js_1.Sequence);
    });
    test('No signatures', () => {
        const response = new HandshakeResponse_1.HandshakeResponse([]);
        const serialization = response.serialize();
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        expect(sequence.valueBlock.value).toHaveLength(1);
    });
    test('One signature', () => {
        const response = new HandshakeResponse_1.HandshakeResponse([SIGNATURE1]);
        const serialization = response.serialize();
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        expect(sequence.valueBlock.value).toHaveLength(1);
        expect(sequence.valueBlock.value[0]).toBeInstanceOf(asn1js_1.Constructed);
        const nonceSignaturesASN1 = sequence.valueBlock.value[0];
        expect(nonceSignaturesASN1.valueBlock.value).toHaveLength(1);
        expect(nonceSignaturesASN1.valueBlock.value[0]).toBeInstanceOf(asn1js_1.OctetString);
        (0, _test_utils_1.expectArrayBuffersToEqual)(SIGNATURE1, nonceSignaturesASN1.valueBlock.value[0].valueBlock.valueHex);
    });
    test('Two signatures', () => {
        const response = new HandshakeResponse_1.HandshakeResponse([SIGNATURE1, SIGNATURE2]);
        const serialization = response.serialize();
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        expect(sequence.valueBlock.value).toHaveLength(1);
        expect(sequence.valueBlock.value[0]).toBeInstanceOf(asn1js_1.Constructed);
        const nonceSignaturesASN1 = sequence.valueBlock.value[0];
        expect(nonceSignaturesASN1.valueBlock.value).toHaveLength(2);
        expect(nonceSignaturesASN1.valueBlock.value[0]).toBeInstanceOf(asn1js_1.OctetString);
        (0, _test_utils_1.expectArrayBuffersToEqual)(SIGNATURE1, nonceSignaturesASN1.valueBlock.value[0].valueBlock.valueHex);
        expect(nonceSignaturesASN1.valueBlock.value[1]).toBeInstanceOf(asn1js_1.OctetString);
        (0, _test_utils_1.expectArrayBuffersToEqual)(SIGNATURE2, nonceSignaturesASN1.valueBlock.value[1].valueBlock.valueHex);
    });
});
describe('deserialize', () => {
    test('Invalid serialization should be refused', () => {
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.Integer({ value: 42 })).toBER();
        expect(() => HandshakeResponse_1.HandshakeResponse.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Handshake response is malformed');
    });
    test('Valid serialization should be accepted', () => {
        const response = new HandshakeResponse_1.HandshakeResponse([SIGNATURE1, SIGNATURE2]);
        const serialization = response.serialize();
        const responseDeserialized = HandshakeResponse_1.HandshakeResponse.deserialize(serialization);
        expect(responseDeserialized.nonceSignatures).toHaveLength(2);
        (0, _test_utils_1.expectArrayBuffersToEqual)(responseDeserialized.nonceSignatures[0], SIGNATURE1);
        (0, _test_utils_1.expectArrayBuffersToEqual)(responseDeserialized.nonceSignatures[1], SIGNATURE2);
    });
});
//# sourceMappingURL=HandshakeResponse.spec.js.map