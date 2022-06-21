"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const asn1js_1 = require("asn1js");
const index_1 = require("../../../index");
const _test_utils_1 = require("../../_test_utils");
const asn1_1 = require("../../asn1");
const _utils_1 = require("../../crypto_wrappers/_utils");
const rsaSigning_1 = require("../../crypto_wrappers/rsaSigning");
const InvalidMessageError_1 = __importDefault(require("../../messages/InvalidMessageError"));
const oids_1 = require("../../oids");
const authorizationSerialized = (0, _test_utils_1.arrayBufferFrom)('The PNRA');
let privateNodeKeyPair;
beforeAll(async () => {
    privateNodeKeyPair = await (0, index_1.generateRSAKeyPair)();
});
describe('serialize', () => {
    test('Private node public key should be honored', async () => {
        const request = new index_1.PrivateNodeRegistrationRequest(privateNodeKeyPair.publicKey, authorizationSerialized);
        const serialization = await request.serialize(privateNodeKeyPair.privateKey);
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        expect((0, _test_utils_1.getAsn1SequenceItem)(sequence, 0)).toHaveProperty('valueBlock.valueHex', (0, _test_utils_1.arrayBufferFrom)(await (0, index_1.derSerializePublicKey)(privateNodeKeyPair.publicKey)));
    });
    test('Authorization should be honored', async () => {
        const request = new index_1.PrivateNodeRegistrationRequest(privateNodeKeyPair.publicKey, authorizationSerialized);
        const serialization = await request.serialize(privateNodeKeyPair.privateKey);
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        expect((0, _test_utils_1.getAsn1SequenceItem)(sequence, 1)).toHaveProperty('valueBlock.valueHex', authorizationSerialized);
    });
    test('Authorization countersignature should be valid', async () => {
        const request = new index_1.PrivateNodeRegistrationRequest(privateNodeKeyPair.publicKey, authorizationSerialized);
        const serialization = await request.serialize(privateNodeKeyPair.privateKey);
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        const signature = (0, _test_utils_1.getAsn1SequenceItem)(sequence, 2).valueBlock.valueHex;
        const expectedPNRACountersignature = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.ObjectIdentifier({
            value: oids_1.RELAYNET_OIDS.NODE_REGISTRATION.AUTHORIZATION_COUNTERSIGNATURE,
        }), new asn1js_1.OctetString({ valueHex: authorizationSerialized })).toBER();
        await expect((0, rsaSigning_1.verify)(signature, privateNodeKeyPair.publicKey, expectedPNRACountersignature)).resolves.toBeTrue();
    });
});
describe('deserialize', () => {
    test('Malformed sequence should be refused', async () => {
        const invalidSerialization = (0, _test_utils_1.arrayBufferFrom)('nope.jpg');
        await expect(index_1.PrivateNodeRegistrationRequest.deserialize(invalidSerialization)).rejects.toEqual(new InvalidMessageError_1.default('Serialization is not a valid PrivateNodeRegistrationRequest'));
    });
    test('Sequence should have at least 3 items', async () => {
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.VisibleString({ value: 'foo' }), new asn1js_1.VisibleString({ value: 'bar' })).toBER();
        await expect(index_1.PrivateNodeRegistrationRequest.deserialize(invalidSerialization)).rejects.toEqual(new InvalidMessageError_1.default('Serialization is not a valid PrivateNodeRegistrationRequest'));
    });
    test('Malformed private node public key should be refused', async () => {
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.VisibleString({ value: 'not a valid public key' }), new asn1js_1.VisibleString({ value: 'foo' }), new asn1js_1.VisibleString({ value: 'bar' })).toBER();
        await expect(index_1.PrivateNodeRegistrationRequest.deserialize(invalidSerialization)).rejects.toEqual(new InvalidMessageError_1.default('Private node public key is not valid'));
    });
    test('Invalid countersignatures should be refused', async () => {
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: await (0, index_1.derSerializePublicKey)(privateNodeKeyPair.publicKey) }), new asn1js_1.VisibleString({ value: 'gateway data' }), new asn1js_1.VisibleString({ value: 'invalid signature' })).toBER();
        await expect(index_1.PrivateNodeRegistrationRequest.deserialize(invalidSerialization)).rejects.toEqual(new InvalidMessageError_1.default('Authorization countersignature is invalid'));
    });
    test('Valid values should be accepted', async () => {
        const request = new index_1.PrivateNodeRegistrationRequest(privateNodeKeyPair.publicKey, authorizationSerialized);
        const serialization = await request.serialize(privateNodeKeyPair.privateKey);
        const requestDeserialized = await index_1.PrivateNodeRegistrationRequest.deserialize(serialization);
        expect((0, index_1.derSerializePublicKey)(requestDeserialized.privateNodePublicKey)).toEqual((0, index_1.derSerializePublicKey)(privateNodeKeyPair.publicKey));
        expect(requestDeserialized.pnraSerialized).toEqual(authorizationSerialized);
    });
});
//# sourceMappingURL=PrivateNodeRegistrationRequest.spec.js.map