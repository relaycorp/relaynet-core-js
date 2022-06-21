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
/* tslint:disable:no-let no-object-mutation */
const asn1js = __importStar(require("asn1js"));
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const _test_utils_1 = require("../../_test_utils");
const _utils_1 = require("../../crypto_wrappers/_utils");
const keys_1 = require("../../crypto_wrappers/keys");
const CertificationPath_1 = require("../../pki/CertificationPath");
const serialization_1 = require("../../ramf/serialization");
const Cargo_1 = __importDefault(require("../Cargo"));
const CertificateRotation_1 = require("../CertificateRotation");
const InvalidMessageError_1 = __importDefault(require("../InvalidMessageError"));
const Parcel_1 = __importDefault(require("../Parcel"));
const ParcelCollectionAck_1 = require("../ParcelCollectionAck");
const CargoMessageSet_1 = __importDefault(require("./CargoMessageSet"));
const STUB_MESSAGE = (0, _test_utils_1.arrayBufferFrom)('hiya');
describe('CargoMessageSet', () => {
    describe('deserialize', () => {
        test('Non-DER-encoded values should be refused', () => {
            const invalidSerialization = (0, buffer_to_arraybuffer_1.default)(Buffer.from('I pretend to be valid'));
            expect(() => CargoMessageSet_1.default.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Serialization is not a valid CargoMessageSet');
        });
        test('Outer value should be an ASN.1 SEQUENCE', () => {
            const asn1Integer = new asn1js.Integer({ value: 1 });
            const invalidSerialization = asn1Integer.toBER(false);
            expect(() => CargoMessageSet_1.default.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Serialization is not a valid CargoMessageSet');
        });
        test('Inner value should be an ASN.1 OCTET STRING', () => {
            const asn1Sequence = new asn1js.Sequence();
            // tslint:disable-next-line:no-object-mutation
            asn1Sequence.valueBlock.value = [new asn1js.Integer({ value: 1 })];
            const invalidSerialization = asn1Sequence.toBER(false);
            expect(() => CargoMessageSet_1.default.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Serialization is not a valid CargoMessageSet');
        });
        test('A sequence without values should be treated as an empty array', () => {
            const asn1Sequence = new asn1js.Sequence();
            const serialization = asn1Sequence.toBER(false);
            const cargoMessages = CargoMessageSet_1.default.deserialize(serialization);
            expect(cargoMessages.messages).toEqual([]);
        });
        test('An empty sequence should be accepted', () => {
            const asn1Sequence = new asn1js.Sequence();
            asn1Sequence.valueBlock.value = [];
            const serialization = asn1Sequence.toBER(false);
            const cargoMessages = CargoMessageSet_1.default.deserialize(serialization);
            expect(cargoMessages.messages).toEqual([]);
        });
        test('A single-item sequence should be accepted', () => {
            const asn1Sequence = new asn1js.Sequence();
            asn1Sequence.valueBlock.value = [new asn1js.OctetString({ valueHex: STUB_MESSAGE })];
            const serialization = asn1Sequence.toBER(false);
            const cargoMessages = CargoMessageSet_1.default.deserialize(serialization);
            expect(cargoMessages.messages).toEqual([STUB_MESSAGE]);
        });
        test('A multi-item sequence should be accepted', () => {
            const messages = [STUB_MESSAGE, (0, _test_utils_1.arrayBufferFrom)('another message')];
            const asn1Sequence = new asn1js.Sequence();
            asn1Sequence.valueBlock.value = messages.map((m) => new asn1js.OctetString({ valueHex: m }));
            const serialization = asn1Sequence.toBER(false);
            const cargoMessages = CargoMessageSet_1.default.deserialize(serialization);
            expect(cargoMessages.messages).toEqual(messages);
        });
    });
    describe('deserializeItem', () => {
        let privateKey;
        let certificate;
        const PCA = new ParcelCollectionAck_1.ParcelCollectionAck('https://sender.endpoint/', 'deadbeef', 'parcel-id');
        beforeAll(async () => {
            const senderKeyPair = await (0, keys_1.generateRSAKeyPair)();
            privateKey = senderKeyPair.privateKey;
            certificate = await (0, _test_utils_1.generateStubCert)({
                issuerPrivateKey: privateKey,
                subjectPublicKey: senderKeyPair.publicKey,
            });
        });
        test('Parcels should be returned', async () => {
            const parcel = new Parcel_1.default('0deadbeef', certificate, Buffer.from('hi'));
            const parcelSerialization = await parcel.serialize(privateKey);
            const item = await CargoMessageSet_1.default.deserializeItem(parcelSerialization);
            expect(item).toBeInstanceOf(Parcel_1.default);
            expect(item).toHaveProperty('id', parcel.id);
        });
        test('PCAs should be returned', async () => {
            const item = await CargoMessageSet_1.default.deserializeItem(await PCA.serialize());
            expect(item).toBeInstanceOf(ParcelCollectionAck_1.ParcelCollectionAck);
            expect(item).toMatchObject(PCA);
        });
        test('Certificate rotations should be returned', async () => {
            const rotation = new CertificateRotation_1.CertificateRotation(new CertificationPath_1.CertificationPath(certificate, [certificate]));
            const item = await CargoMessageSet_1.default.deserializeItem(rotation.serialize());
            expect(item).toBeInstanceOf(CertificateRotation_1.CertificateRotation);
            const rotationDeserialized = item;
            expect(rotationDeserialized.certificationPath.leafCertificate.isEqual(certificate)).toBeTrue();
            expect(rotationDeserialized.certificationPath.certificateAuthorities[0].isEqual(certificate)).toBeTrue();
        });
        test('An error should be thrown when non-RAMF message is found', async () => {
            const invalidItemSerialized = (0, _test_utils_1.arrayBufferFrom)('Not RAMF');
            await expect(CargoMessageSet_1.default.deserializeItem(invalidItemSerialized)).rejects.toThrow(/Value is not a valid Cargo Message Set item/);
        });
        test('An error should be yielded when unsupported RAMF message is found', async () => {
            const innerCargo = new Cargo_1.default('address', certificate, Buffer.from('hi'));
            const cargoSerialization = await innerCargo.serialize(privateKey);
            await expect(CargoMessageSet_1.default.deserializeItem(cargoSerialization)).rejects.toThrow(/Value is not a valid Cargo Message Set item/);
        });
    });
    describe('batchMessagesSerialized', () => {
        const EXPIRY_DATE = new Date();
        test('Zero messages should result in zero batches', async () => {
            const messages = (0, _test_utils_1.arrayToAsyncIterable)([]);
            const batches = await (0, _test_utils_1.asyncIterableToArray)(CargoMessageSet_1.default.batchMessagesSerialized(messages));
            expect(batches).toHaveLength(0);
        });
        test('A single message should result in one batch', async () => {
            const messageSerialized = (0, _test_utils_1.arrayBufferFrom)('I am a parcel.');
            const messages = (0, _test_utils_1.arrayToAsyncIterable)([{ messageSerialized, expiryDate: EXPIRY_DATE }]);
            const batches = await (0, _test_utils_1.asyncIterableToArray)(CargoMessageSet_1.default.batchMessagesSerialized(messages));
            expect(batches).toHaveLength(1);
            const messageSet = CargoMessageSet_1.default.deserialize(batches[0].messageSerialized);
            expect(messageSet.messages).toEqual([messageSerialized]);
        });
        test('Multiple small messages should be put in the same batch', async () => {
            const messagesSerialized = [
                { messageSerialized: (0, _test_utils_1.arrayBufferFrom)('I am a parcel.'), expiryDate: EXPIRY_DATE },
                { messageSerialized: (0, _test_utils_1.arrayBufferFrom)('And I am also a parcel.'), expiryDate: EXPIRY_DATE },
            ];
            const messages = (0, _test_utils_1.arrayToAsyncIterable)(messagesSerialized);
            const batches = await (0, _test_utils_1.asyncIterableToArray)(CargoMessageSet_1.default.batchMessagesSerialized(messages));
            expect(batches).toHaveLength(1);
            const messageSet = CargoMessageSet_1.default.deserialize(batches[0].messageSerialized);
            expect(messageSet.messages).toEqual(messagesSerialized.map((m) => m.messageSerialized));
        });
        test('Messages should be put into as few batches as possible', async () => {
            const octetsIn3Mib = 3145728;
            const messageSerialized = (0, _test_utils_1.arrayBufferFrom)('a'.repeat(octetsIn3Mib));
            const messages = (0, _test_utils_1.arrayToAsyncIterable)([
                { messageSerialized, expiryDate: EXPIRY_DATE },
                { messageSerialized, expiryDate: EXPIRY_DATE },
                { messageSerialized, expiryDate: EXPIRY_DATE },
            ]);
            const batches = await (0, _test_utils_1.asyncIterableToArray)(CargoMessageSet_1.default.batchMessagesSerialized(messages));
            expect(batches).toHaveLength(2);
            const messageSet1 = CargoMessageSet_1.default.deserialize(batches[0].messageSerialized);
            expect(messageSet1.messages).toEqual([messageSerialized, messageSerialized]);
            const messageSet2 = CargoMessageSet_1.default.deserialize(batches[1].messageSerialized);
            expect(messageSet2.messages).toEqual([messageSerialized]);
        });
        test('Messages exceeding the max per-message size should be refused', async () => {
            const messageSerialized = (0, _test_utils_1.arrayBufferFrom)('a'.repeat(CargoMessageSet_1.default.MAX_MESSAGE_LENGTH + 1));
            const messages = (0, _test_utils_1.arrayToAsyncIterable)([{ messageSerialized, expiryDate: EXPIRY_DATE }]);
            await expect((0, _test_utils_1.asyncIterableToArray)(CargoMessageSet_1.default.batchMessagesSerialized(messages))).rejects.toEqual(new InvalidMessageError_1.default(`Cargo messages must not exceed ${CargoMessageSet_1.default.MAX_MESSAGE_LENGTH} octets ` +
                `(got one with ${messageSerialized.byteLength} octets)`));
        });
        test('A message with the largest possible length should be included', async () => {
            const messageSerialized = (0, _test_utils_1.arrayBufferFrom)('a'.repeat(CargoMessageSet_1.default.MAX_MESSAGE_LENGTH));
            const messages = (0, _test_utils_1.arrayToAsyncIterable)([{ messageSerialized, expiryDate: EXPIRY_DATE }]);
            const batches = await (0, _test_utils_1.asyncIterableToArray)(CargoMessageSet_1.default.batchMessagesSerialized(messages));
            expect(batches).toHaveLength(1);
            expect(batches[0].messageSerialized.byteLength).toEqual(serialization_1.MAX_SDU_PLAINTEXT_LENGTH);
            const messageSet = CargoMessageSet_1.default.deserialize(batches[0].messageSerialized);
            expect(messageSet.messages).toEqual([messageSerialized]);
        });
        test('Messages collectively reaching max length should be placed together', async () => {
            const messageSerialized1 = (0, _test_utils_1.arrayBufferFrom)('a'.repeat(CargoMessageSet_1.default.MAX_MESSAGE_LENGTH / 2 - 3));
            const messageSerialized2 = (0, _test_utils_1.arrayBufferFrom)('a'.repeat(CargoMessageSet_1.default.MAX_MESSAGE_LENGTH / 2 - 2));
            const messages = (0, _test_utils_1.arrayToAsyncIterable)([
                { messageSerialized: messageSerialized1, expiryDate: EXPIRY_DATE },
                { messageSerialized: messageSerialized2, expiryDate: EXPIRY_DATE },
            ]);
            const batches = await (0, _test_utils_1.asyncIterableToArray)(CargoMessageSet_1.default.batchMessagesSerialized(messages));
            expect(batches).toHaveLength(1);
            expect(batches[0].messageSerialized.byteLength).toEqual(serialization_1.MAX_SDU_PLAINTEXT_LENGTH);
            const messageSet = CargoMessageSet_1.default.deserialize(batches[0].messageSerialized);
            expect(messageSet.messages).toEqual([messageSerialized1, messageSerialized2]);
        });
        test('Expiry date of batch should be that of its message with latest expiry', async () => {
            const octetsIn3Mib = 3145728;
            const messageSerialized = (0, _test_utils_1.arrayBufferFrom)('a'.repeat(octetsIn3Mib));
            const message1ExpiryDate = new Date(2017, 2, 1);
            const message2ExpiryDate = new Date(2017, 1, 2);
            const message3ExpiryDate = new Date(2017, 1, 3);
            const message4ExpiryDate = new Date(2017, 1, 4);
            const messages = (0, _test_utils_1.arrayToAsyncIterable)([
                { messageSerialized, expiryDate: message1ExpiryDate },
                { messageSerialized, expiryDate: message2ExpiryDate },
                { messageSerialized, expiryDate: message3ExpiryDate },
                { messageSerialized, expiryDate: message4ExpiryDate },
            ]);
            const batches = await (0, _test_utils_1.asyncIterableToArray)(CargoMessageSet_1.default.batchMessagesSerialized(messages));
            expect(batches).toHaveLength(2);
            expect(batches[0].expiryDate).toEqual(message1ExpiryDate);
            expect(batches[1].expiryDate).toEqual(message4ExpiryDate);
        });
    });
    describe('serialize', () => {
        test('An empty array should serialized as such', () => {
            const payload = new CargoMessageSet_1.default([]);
            const serialization = payload.serialize();
            const deserialization = (0, _utils_1.derDeserialize)(serialization);
            expect(deserialization).toBeInstanceOf(asn1js.Sequence);
            expect(deserialization.valueBlock.value).toHaveLength(0);
        });
        test('A one-item array should serialized as such', () => {
            const payload = new CargoMessageSet_1.default([STUB_MESSAGE]);
            const serialization = payload.serialize();
            const deserialization = (0, _utils_1.derDeserialize)(serialization);
            expect(deserialization).toBeInstanceOf(asn1js.Sequence);
            expect(deserialization.valueBlock.value).toHaveLength(1);
            const stubMessageAsn1 = deserialization.valueBlock.value[0];
            expect(stubMessageAsn1).toBeInstanceOf(asn1js.OctetString);
            (0, _test_utils_1.expectArrayBuffersToEqual)(stubMessageAsn1.valueBlock.valueHex, STUB_MESSAGE);
        });
        test('A multi-item array should serialized as such', () => {
            const stubMessages = [STUB_MESSAGE, (0, _test_utils_1.arrayBufferFrom)('bye')];
            const payload = new CargoMessageSet_1.default(stubMessages);
            const serialization = payload.serialize();
            const deserialization = (0, _utils_1.derDeserialize)(serialization);
            expect(deserialization).toBeInstanceOf(asn1js.Sequence);
            expect(deserialization.valueBlock.value).toHaveLength(stubMessages.length);
            for (let index = 0; index < stubMessages.length; index++) {
                const messageAsn1 = deserialization.valueBlock.value[index];
                expect(messageAsn1).toBeInstanceOf(asn1js.OctetString);
                (0, _test_utils_1.expectArrayBuffersToEqual)(messageAsn1.valueBlock.valueHex, stubMessages[index]);
            }
        });
    });
});
//# sourceMappingURL=CargoMessageSet.spec.js.map