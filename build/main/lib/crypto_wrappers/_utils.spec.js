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
const webcrypto_1 = require("@peculiar/webcrypto");
const asn1js = __importStar(require("asn1js"));
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const pkijs = __importStar(require("pkijs"));
const _utils_1 = require("./_utils");
const stubCrypto = new webcrypto_1.Crypto();
jest.mock('pkijs');
describe('getPkijsCrypto', () => {
    test('It should pass on the crypto object it got', () => {
        // @ts-ignore
        pkijs.getCrypto.mockReturnValue(stubCrypto.subtle);
        const crypto = (0, _utils_1.getPkijsCrypto)();
        expect(crypto).toBe(stubCrypto.subtle);
    });
    test('It should error out if there is no crypto object', () => {
        // @ts-ignore
        pkijs.getCrypto.mockReturnValue(undefined);
        expect(_utils_1.getPkijsCrypto).toThrow('PKI.js crypto engine is undefined');
    });
});
describe('deserializeDer', () => {
    test('should return ASN.1 object given a valid DER-encoded buffer', () => {
        const asn1Value = new asn1js.Integer({ value: 3 });
        const derValue = asn1Value.toBER(false);
        const deserializedValue = (0, _utils_1.derDeserialize)(derValue);
        expect(deserializedValue).toHaveProperty('idBlock.tagClass', asn1Value.idBlock.tagClass);
        expect(deserializedValue).toHaveProperty('idBlock.tagNumber', asn1Value.idBlock.tagNumber);
        expect(deserializedValue).toHaveProperty('valueBlock.valueDec', asn1Value.valueBlock.valueDec);
    });
    test('should fail when passed a non-DER encoded value', () => {
        const invalidDerValue = (0, buffer_to_arraybuffer_1.default)(Buffer.from('hi'));
        expect(() => (0, _utils_1.derDeserialize)(invalidDerValue)).toThrowError(new Error('Value is not DER-encoded'));
    });
});
test('generateRandom64BitValue() should generate a cryptographically secure value', () => {
    const expectedBytes = [1, 2, 3, 4, 5, 6, 7, 8];
    const mockWebcrypto = {
        getRandomValues: jest.fn().mockImplementation((array) => array.set(expectedBytes)),
    };
    // @ts-ignore
    pkijs.getCrypto.mockReset();
    // @ts-ignore
    pkijs.getCrypto.mockReturnValue(mockWebcrypto);
    const randomValue = (0, _utils_1.generateRandom64BitValue)();
    expect(randomValue).toBeInstanceOf(ArrayBuffer);
    expect(randomValue).toHaveProperty('byteLength', 8);
    const expectedGeneratedValue = new ArrayBuffer(8);
    const expectedGeneratedValueView = new Uint8Array(expectedGeneratedValue);
    expectedGeneratedValueView.set(expectedBytes);
    expect(randomValue).toEqual(expectedGeneratedValue);
});
//# sourceMappingURL=_utils.spec.js.map