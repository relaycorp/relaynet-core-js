"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const asn1js_1 = require("asn1js");
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const _test_utils_1 = require("../_test_utils");
const asn1_1 = require("../asn1");
const _utils_1 = require("../crypto_wrappers/_utils");
const keys_1 = require("../crypto_wrappers/keys");
const errors_1 = require("./errors");
const PublicNodeConnectionParams_1 = require("./PublicNodeConnectionParams");
const PUBLIC_ADDRESS = 'example.com';
let identityKey;
let sessionKey;
beforeAll(async () => {
    const identityKeyPair = await (0, keys_1.generateRSAKeyPair)();
    identityKey = identityKeyPair.publicKey;
    const sessionKeyPair = await (0, keys_1.generateECDHKeyPair)();
    sessionKey = {
        keyId: Buffer.from('key id'),
        publicKey: sessionKeyPair.publicKey,
    };
});
describe('serialize', () => {
    test('Public address should be serialized', async () => {
        const params = new PublicNodeConnectionParams_1.PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);
        const serialization = await params.serialize();
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        expect(sequence).toBeInstanceOf(asn1js_1.Sequence);
        expect(sequence.valueBlock.value[0]).toHaveProperty('valueBlock.valueHex', (0, _test_utils_1.arrayBufferFrom)(PUBLIC_ADDRESS));
    });
    test('Identity key should be serialized', async () => {
        const params = new PublicNodeConnectionParams_1.PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);
        const serialization = await params.serialize();
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        expect(sequence).toBeInstanceOf(asn1js_1.Sequence);
        expect(sequence.valueBlock.value[1]).toHaveProperty('valueBlock.valueHex', (0, buffer_to_arraybuffer_1.default)(await (0, keys_1.derSerializePublicKey)(identityKey)));
    });
    describe('Session key', () => {
        test('Session key should be a CONSTRUCTED value', async () => {
            const params = new PublicNodeConnectionParams_1.PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);
            const serialization = await params.serialize();
            const sequence = (0, _utils_1.derDeserialize)(serialization);
            const sessionKeySequence = sequence.valueBlock.value[2];
            expect(sessionKeySequence).toBeInstanceOf(asn1js_1.Constructed);
        });
        test('Id should be serialized', async () => {
            const params = new PublicNodeConnectionParams_1.PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);
            const serialization = await params.serialize();
            const sequence = (0, _utils_1.derDeserialize)(serialization);
            expect(sequence.valueBlock.value[2].valueBlock.value[0]).toHaveProperty('valueBlock.valueHex', (0, buffer_to_arraybuffer_1.default)(sessionKey.keyId));
        });
        test('Public key should be serialized', async () => {
            const params = new PublicNodeConnectionParams_1.PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);
            const serialization = await params.serialize();
            const sequence = (0, _utils_1.derDeserialize)(serialization);
            expect(sequence.valueBlock.value[2].valueBlock.value[1]).toHaveProperty('valueBlock.valueHex', (0, buffer_to_arraybuffer_1.default)(await (0, keys_1.derSerializePublicKey)(sessionKey.publicKey)));
        });
    });
});
describe('deserialize', () => {
    let identityKeySerialized;
    let sessionKeySerialized;
    beforeAll(async () => {
        identityKeySerialized = (0, buffer_to_arraybuffer_1.default)(await (0, keys_1.derSerializePublicKey)(identityKey));
        sessionKeySerialized = (0, buffer_to_arraybuffer_1.default)(await (0, keys_1.derSerializePublicKey)(sessionKey.publicKey));
    });
    let sessionKeySequence;
    beforeAll(() => {
        sessionKeySequence = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: (0, buffer_to_arraybuffer_1.default)(sessionKey.keyId) }), new asn1js_1.OctetString({ valueHex: sessionKeySerialized }));
    });
    const malformedErrorMessage = 'Serialization is not a valid PublicNodeConnectionParams';
    test('Serialization should be DER sequence', async () => {
        const invalidSerialization = (0, _test_utils_1.arrayBufferFrom)('nope.jpg');
        await expect(PublicNodeConnectionParams_1.PublicNodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrowWithMessage(errors_1.InvalidPublicNodeConnectionParams, malformedErrorMessage);
    });
    test('Sequence should have at least three items', async () => {
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: (0, _test_utils_1.arrayBufferFrom)('nope.jpg') }), new asn1js_1.OctetString({ valueHex: (0, _test_utils_1.arrayBufferFrom)('whoops.jpg') })).toBER();
        await expect(PublicNodeConnectionParams_1.PublicNodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrowWithMessage(errors_1.InvalidPublicNodeConnectionParams, malformedErrorMessage);
    });
    test('Public address should be syntactically valid', async () => {
        const invalidPublicAddress = 'not a public address';
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.VisibleString({ value: invalidPublicAddress }), new asn1js_1.OctetString({ valueHex: identityKeySerialized }), sessionKeySequence).toBER();
        await expect(PublicNodeConnectionParams_1.PublicNodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrow(new errors_1.InvalidPublicNodeConnectionParams(`Public address is syntactically invalid (${invalidPublicAddress})`));
    });
    test('Identity key should be a valid RSA public key', async () => {
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.VisibleString({ value: PUBLIC_ADDRESS }), new asn1js_1.OctetString({
            valueHex: sessionKeySerialized, // Wrong type of key
        }), sessionKeySequence).toBER();
        await expect(PublicNodeConnectionParams_1.PublicNodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrowWithMessage(errors_1.InvalidPublicNodeConnectionParams, /^Identity key is not a valid RSA public key/);
    });
    describe('Session key', () => {
        test('SEQUENCE should contain at least two items', async () => {
            const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.VisibleString({ value: PUBLIC_ADDRESS }), new asn1js_1.OctetString({ valueHex: identityKeySerialized }), (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: (0, buffer_to_arraybuffer_1.default)(sessionKey.keyId) }))).toBER();
            await expect(PublicNodeConnectionParams_1.PublicNodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrowWithMessage(errors_1.InvalidPublicNodeConnectionParams, 'Session key should have at least two items');
        });
        test('Session key should be a valid ECDH public key', async () => {
            const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.VisibleString({ value: PUBLIC_ADDRESS }), new asn1js_1.OctetString({ valueHex: identityKeySerialized }), (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: (0, buffer_to_arraybuffer_1.default)(sessionKey.keyId) }), new asn1js_1.OctetString({
                valueHex: identityKeySerialized, // Wrong type of key
            }))).toBER();
            await expect(PublicNodeConnectionParams_1.PublicNodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrowWithMessage(errors_1.InvalidPublicNodeConnectionParams, /^Session key is not a valid ECDH public key/);
        });
    });
    test('Valid serialization should be deserialized', async () => {
        const params = new PublicNodeConnectionParams_1.PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);
        const serialization = await params.serialize();
        const paramsDeserialized = await PublicNodeConnectionParams_1.PublicNodeConnectionParams.deserialize(serialization);
        expect(paramsDeserialized.publicAddress).toEqual(PUBLIC_ADDRESS);
        await expect((0, keys_1.derSerializePublicKey)(paramsDeserialized.identityKey)).resolves.toEqual(Buffer.from(identityKeySerialized));
        await expect(paramsDeserialized.sessionKey.keyId).toEqual(sessionKey.keyId);
        await expect((0, keys_1.derSerializePublicKey)(paramsDeserialized.sessionKey.publicKey)).resolves.toEqual(Buffer.from(sessionKeySerialized));
    });
});
//# sourceMappingURL=PublicNodeConnectionParams.spec.js.map