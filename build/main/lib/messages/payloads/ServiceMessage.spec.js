"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const asn1js = __importStar(require("asn1js"));
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const _test_utils_1 = require("../../_test_utils");
const asn1_1 = require("../../asn1");
const _utils_1 = require("../../crypto_wrappers/_utils");
const InvalidMessageError_1 = __importDefault(require("../InvalidMessageError"));
const ServiceMessage_1 = __importDefault(require("./ServiceMessage"));
const TYPE = 'the type';
const CONTENT = Buffer.from('the content');
describe('ServiceMessage', () => {
    describe('serialize', () => {
        test('Type should be serialized', () => {
            const message = new ServiceMessage_1.default(TYPE, CONTENT);
            const serialization = message.serialize();
            const sequence = (0, _utils_1.derDeserialize)(serialization);
            expect(sequence).toBeInstanceOf(asn1js.Sequence);
            const typeASN1 = (0, _test_utils_1.getAsn1SequenceItem)(sequence, 0);
            expect(typeASN1.valueBlock.valueHex).toEqual((0, _test_utils_1.arrayBufferFrom)(TYPE));
        });
        test('Content should be serialized', () => {
            const message = new ServiceMessage_1.default(TYPE, CONTENT);
            const serialization = message.serialize();
            const sequence = (0, _utils_1.derDeserialize)(serialization);
            expect(sequence).toBeInstanceOf(asn1js.Sequence);
            const contentASN1 = (0, _test_utils_1.getAsn1SequenceItem)(sequence, 1);
            (0, _test_utils_1.expectArrayBuffersToEqual)((0, buffer_to_arraybuffer_1.default)(CONTENT), contentASN1.valueBlock.valueHex);
        });
    });
    describe('deserialize', () => {
        test('Serialization should be DER sequence', () => {
            const invalidSerialization = new asn1js.Null().toBER(false);
            expect(() => ServiceMessage_1.default.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Invalid service message serialization');
        });
        test('Sequence should have at least two items', () => {
            const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js.VisibleString({ value: 'foo' })).toBER();
            expect(() => ServiceMessage_1.default.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Invalid service message serialization');
        });
        test('Valid service message should be accepted', () => {
            const originalMessage = new ServiceMessage_1.default(TYPE, Buffer.from('Hey'));
            const serialization = (0, buffer_to_arraybuffer_1.default)(Buffer.from(originalMessage.serialize()));
            const finalMessage = ServiceMessage_1.default.deserialize(serialization);
            expect(finalMessage.type).toEqual(originalMessage.type);
            expect(finalMessage.content).toEqual(originalMessage.content);
        });
    });
});
//# sourceMappingURL=ServiceMessage.spec.js.map