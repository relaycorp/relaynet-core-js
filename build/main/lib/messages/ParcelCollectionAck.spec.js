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
const _test_utils_1 = require("../_test_utils");
const _utils_1 = require("../crypto_wrappers/_utils");
const InvalidMessageError_1 = __importDefault(require("./InvalidMessageError"));
const ParcelCollectionAck_1 = require("./ParcelCollectionAck");
describe('ParcelCollectionAck', () => {
    const SENDER_ENDPOINT_PRIVATE_ADDRESS = '0deadbeef';
    const RECIPIENT_ENDPOINT_ADDRESS = 'https://example.com';
    const PARCEL_ID = 'the-parcel-id';
    describe('serialize', () => {
        test('Serialization should start with format signature', () => {
            const pca = new ParcelCollectionAck_1.ParcelCollectionAck(SENDER_ENDPOINT_PRIVATE_ADDRESS, RECIPIENT_ENDPOINT_ADDRESS, PARCEL_ID);
            const pcaSerialized = pca.serialize();
            const expectedFormatSignature = Buffer.concat([
                Buffer.from('Relaynet'),
                Buffer.from([0x51, 0x00]),
            ]);
            expect(Buffer.from(pcaSerialized).slice(0, 10)).toEqual(expectedFormatSignature);
        });
        test('An ACK should be serialized as a 3-item sequence', () => {
            const pca = new ParcelCollectionAck_1.ParcelCollectionAck(SENDER_ENDPOINT_PRIVATE_ADDRESS, RECIPIENT_ENDPOINT_ADDRESS, PARCEL_ID);
            const pcaBlock = parsePCA(pca.serialize());
            expect(pcaBlock).toBeInstanceOf(asn1js.Sequence);
            const pcaSequenceBlock = pcaBlock;
            const pcaSequenceItems = pcaSequenceBlock.valueBlock.value;
            expect(pcaSequenceItems).toHaveLength(3);
            expect(pcaSequenceItems[0].valueBlock.valueHex).toEqual((0, _test_utils_1.arrayBufferFrom)(SENDER_ENDPOINT_PRIVATE_ADDRESS));
            expect(pcaSequenceItems[1].valueBlock.valueHex).toEqual((0, _test_utils_1.arrayBufferFrom)(RECIPIENT_ENDPOINT_ADDRESS));
            expect(pcaSequenceItems[2].valueBlock.valueHex).toEqual((0, _test_utils_1.arrayBufferFrom)(PARCEL_ID));
        });
        function skipFormatSignatureFromSerialization(pcaSerialized) {
            return pcaSerialized.slice(10);
        }
        function parsePCA(pcaSerialized) {
            const derSequenceSerialized = skipFormatSignatureFromSerialization(pcaSerialized);
            return (0, _utils_1.derDeserialize)(derSequenceSerialized);
        }
    });
    describe('deserialize', () => {
        test('Serialization should start with format signature', () => {
            const invalidSerialization = (0, _test_utils_1.arrayBufferFrom)('RelaynetA0');
            expect(() => ParcelCollectionAck_1.ParcelCollectionAck.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Format signature should be that of a PCA');
        });
        test('ACK should be refused if it has fewer than 3 items', () => {
            // Pass an ACK with 2 VisibleStrings instead of 3
            const invalidSerialization = (0, _test_utils_1.arrayBufferFrom)([
                ...ParcelCollectionAck_1.ParcelCollectionAck.FORMAT_SIGNATURE,
                ...Buffer.from(new asn1js.Sequence({
                    value: [new asn1js.VisibleString(), new asn1js.VisibleString()],
                }).toBER(false)),
            ]);
            expect(() => ParcelCollectionAck_1.ParcelCollectionAck.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'PCA did not meet required structure');
        });
        test('Each ACK should be a three-item sequence of VisibleStrings', () => {
            const invalidSerialization = (0, _test_utils_1.arrayBufferFrom)([
                ...ParcelCollectionAck_1.ParcelCollectionAck.FORMAT_SIGNATURE,
                ...Buffer.from(new asn1js.Sequence({
                    value: [
                        new asn1js.VisibleString(),
                        new asn1js.Integer({ value: 42 }),
                        new asn1js.VisibleString(),
                    ],
                }).toBER(false)),
            ]);
            expect(() => ParcelCollectionAck_1.ParcelCollectionAck.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'PCA did not meet required structure');
        });
        test('A new instance should be returned if serialization is valid', () => {
            const pca = new ParcelCollectionAck_1.ParcelCollectionAck(SENDER_ENDPOINT_PRIVATE_ADDRESS, RECIPIENT_ENDPOINT_ADDRESS, PARCEL_ID);
            const pcaDeserialized = ParcelCollectionAck_1.ParcelCollectionAck.deserialize(pca.serialize());
            expect(pcaDeserialized.senderEndpointPrivateAddress).toEqual(SENDER_ENDPOINT_PRIVATE_ADDRESS);
            expect(pcaDeserialized.recipientEndpointAddress).toEqual(RECIPIENT_ENDPOINT_ADDRESS);
            expect(pcaDeserialized.parcelId).toEqual(PARCEL_ID);
        });
    });
});
//# sourceMappingURL=ParcelCollectionAck.spec.js.map