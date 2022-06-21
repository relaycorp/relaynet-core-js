"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const asn1js_1 = require("asn1js");
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const _test_utils_1 = require("../../_test_utils");
const asn1_1 = require("../../asn1");
const _utils_1 = require("../../crypto_wrappers/_utils");
const keys_1 = require("../../crypto_wrappers/keys");
const InvalidMessageError_1 = __importDefault(require("../../messages/InvalidMessageError"));
const SessionKeyPair_1 = require("../../SessionKeyPair");
const PrivateNodeRegistration_1 = require("./PrivateNodeRegistration");
let privateNodeCertificate;
let gatewayCertificate;
let sessionKey;
beforeAll(async () => {
    privateNodeCertificate = await (0, _test_utils_1.generateStubCert)();
    gatewayCertificate = await (0, _test_utils_1.generateStubCert)();
    sessionKey = (await SessionKeyPair_1.SessionKeyPair.generate()).sessionKey;
});
describe('serialize', () => {
    test('Private node certificate should be serialized', async () => {
        const registration = new PrivateNodeRegistration_1.PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate);
        const serialization = await registration.serialize();
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        expect(sequence).toBeInstanceOf(asn1js_1.Sequence);
        expect(sequence.valueBlock.value[0]).toHaveProperty('valueBlock.valueHex', privateNodeCertificate.serialize());
    });
    test('Gateway certificate should be serialized', async () => {
        const registration = new PrivateNodeRegistration_1.PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate);
        const serialization = await registration.serialize();
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        expect(sequence).toBeInstanceOf(asn1js_1.Sequence);
        expect(sequence.valueBlock.value[1]).toHaveProperty('valueBlock.valueHex', gatewayCertificate.serialize());
    });
    describe('Session key', () => {
        test('Session key should be absent from serialization if it does not exist', async () => {
            const registration = new PrivateNodeRegistration_1.PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate);
            const serialization = await registration.serialize();
            const sequence = (0, _utils_1.derDeserialize)(serialization);
            expect(sequence.valueBlock.value).toHaveLength(2);
        });
        test('Session key should be a CONSTRUCTED value', async () => {
            const registration = new PrivateNodeRegistration_1.PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate, sessionKey);
            const serialization = await registration.serialize();
            const sequence = (0, _utils_1.derDeserialize)(serialization);
            const sessionKeySequence = sequence.valueBlock.value[2];
            expect(sessionKeySequence).toBeInstanceOf(asn1js_1.Constructed);
        });
        test('Key id should be serialized', async () => {
            const registration = new PrivateNodeRegistration_1.PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate, sessionKey);
            const serialization = await registration.serialize();
            const sequence = (0, _utils_1.derDeserialize)(serialization);
            expect(sequence.valueBlock.value[2].valueBlock.value[0]).toHaveProperty('valueBlock.valueHex', (0, buffer_to_arraybuffer_1.default)(sessionKey.keyId));
        });
        test('Public key should be serialized', async () => {
            const registration = new PrivateNodeRegistration_1.PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate, sessionKey);
            const serialization = await registration.serialize();
            const sequence = await (0, _utils_1.derDeserialize)(serialization);
            expect(sequence.valueBlock.value[2].valueBlock.value[1]).toHaveProperty('valueBlock.valueHex', (0, buffer_to_arraybuffer_1.default)(await (0, keys_1.derSerializePublicKey)(sessionKey.publicKey)));
        });
    });
});
describe('deserialize', () => {
    test('Serialization should be DER sequence', async () => {
        const invalidSerialization = (0, _test_utils_1.arrayBufferFrom)('nope.jpg');
        await expect(PrivateNodeRegistration_1.PrivateNodeRegistration.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidMessageError_1.default, 'Serialization is not a valid PrivateNodeRegistration');
    });
    test('Sequence should have at least two items', async () => {
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: (0, _test_utils_1.arrayBufferFrom)('nope.jpg') })).toBER();
        await expect(() => PrivateNodeRegistration_1.PrivateNodeRegistration.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidMessageError_1.default, 'Serialization is not a valid PrivateNodeRegistration');
    });
    test('Invalid private node certificates should be refused', async () => {
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: (0, _test_utils_1.arrayBufferFrom)('not a certificate') }), new asn1js_1.OctetString({ valueHex: gatewayCertificate.serialize() })).toBER();
        await expect(() => PrivateNodeRegistration_1.PrivateNodeRegistration.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidMessageError_1.default, /^Private node certificate is invalid:/);
    });
    test('Invalid gateway certificates should be refused', async () => {
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: gatewayCertificate.serialize() }), new asn1js_1.OctetString({ valueHex: (0, _test_utils_1.arrayBufferFrom)('not a certificate') })).toBER();
        await expect(() => PrivateNodeRegistration_1.PrivateNodeRegistration.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidMessageError_1.default, /^Gateway certificate is invalid:/);
    });
    describe('Session key', () => {
        test('SEQUENCE should contain at least two items', async () => {
            const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: gatewayCertificate.serialize() }), new asn1js_1.OctetString({ valueHex: privateNodeCertificate.serialize() }), (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: (0, buffer_to_arraybuffer_1.default)(sessionKey.keyId) }))).toBER();
            await expect(() => PrivateNodeRegistration_1.PrivateNodeRegistration.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidMessageError_1.default, 'Session key SEQUENCE should have at least 2 items');
        });
        test('Session key should be a valid ECDH public key', async () => {
            const invalidRegistration = new PrivateNodeRegistration_1.PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate, {
                keyId: sessionKey.keyId,
                publicKey: await gatewayCertificate.getPublicKey(), // Invalid key type (RSA)
            });
            const invalidSerialization = await invalidRegistration.serialize();
            await expect(() => PrivateNodeRegistration_1.PrivateNodeRegistration.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidMessageError_1.default, /^Session key is not a valid ECDH public key:/);
        });
    });
    test('Valid registration with session key should be accepted', async () => {
        const registration = new PrivateNodeRegistration_1.PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate, sessionKey);
        const serialization = await registration.serialize();
        const registrationDeserialized = await PrivateNodeRegistration_1.PrivateNodeRegistration.deserialize(serialization);
        expect(registrationDeserialized.privateNodeCertificate.isEqual(privateNodeCertificate)).toBeTrue();
        expect(registrationDeserialized.gatewayCertificate.isEqual(gatewayCertificate)).toBeTrue();
        expect(registrationDeserialized.sessionKey.keyId).toEqual(sessionKey.keyId);
        await expect((0, keys_1.derSerializePublicKey)(registrationDeserialized.sessionKey.publicKey)).resolves.toEqual(await (0, keys_1.derSerializePublicKey)(sessionKey.publicKey));
    });
    test('Valid registration without session key should be accepted', async () => {
        const registration = new PrivateNodeRegistration_1.PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate);
        const serialization = await registration.serialize();
        const registrationDeserialized = await PrivateNodeRegistration_1.PrivateNodeRegistration.deserialize(serialization);
        expect(registrationDeserialized.privateNodeCertificate.isEqual(privateNodeCertificate)).toBeTrue();
        expect(registrationDeserialized.gatewayCertificate.isEqual(gatewayCertificate)).toBeTrue();
    });
});
//# sourceMappingURL=PrivateNodeRegistration.spec.js.map