"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const asn1js_1 = require("asn1js");
const moment_1 = __importDefault(require("moment"));
const index_1 = require("../../../index");
const _test_utils_1 = require("../../_test_utils");
const asn1_1 = require("../../asn1");
const _utils_1 = require("../../crypto_wrappers/_utils");
const rsaSigning_1 = require("../../crypto_wrappers/rsaSigning");
const InvalidMessageError_1 = __importDefault(require("../../messages/InvalidMessageError"));
const oids_1 = require("../../oids");
const PrivateNodeRegistrationAuthorization_1 = require("./PrivateNodeRegistrationAuthorization");
describe('PrivateNodeRegistrationAuthorization', () => {
    const expiryDate = (0, moment_1.default)().millisecond(0).add(1, 'days').toDate();
    const gatewayData = (0, _test_utils_1.arrayBufferFrom)('This is the gateway data');
    // tslint:disable-next-line:no-let
    let gatewayKeyPair;
    beforeAll(async () => {
        gatewayKeyPair = await (0, index_1.generateRSAKeyPair)();
    });
    describe('serialize', () => {
        const authorization = new PrivateNodeRegistrationAuthorization_1.PrivateNodeRegistrationAuthorization(expiryDate, gatewayData);
        test('Serialization should be a sequence', async () => {
            const serialization = await authorization.serialize(gatewayKeyPair.privateKey);
            const sequence = (0, _utils_1.derDeserialize)(serialization);
            expect(sequence).toBeInstanceOf(asn1js_1.Sequence);
        });
        test('Expiry date should be honored', async () => {
            const serialization = await authorization.serialize(gatewayKeyPair.privateKey);
            const sequence = (0, _utils_1.derDeserialize)(serialization);
            const expiryDateASN1 = sequence.valueBlock.value[0];
            expect(expiryDateASN1.valueBlock.valueHex).toEqual((0, asn1_1.dateToASN1DateTimeInUTC)(expiryDate).valueBlock.valueHex);
        });
        test('Gateway data should be honored', async () => {
            const serialization = await authorization.serialize(gatewayKeyPair.privateKey);
            const sequence = (0, _utils_1.derDeserialize)(serialization);
            const gatewayDataASN1 = sequence.valueBlock.value[1];
            expect(gatewayDataASN1.valueBlock.valueHex).toEqual(gatewayData);
        });
        test('Signature should be valid', async () => {
            const serialization = await authorization.serialize(gatewayKeyPair.privateKey);
            const sequence = (0, _utils_1.derDeserialize)(serialization);
            const signatureASN1 = sequence.valueBlock.value[2];
            const signature = signatureASN1.valueBlock.valueHex;
            const expectedPlaintext = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.ObjectIdentifier({ value: oids_1.RELAYNET_OIDS.NODE_REGISTRATION.AUTHORIZATION }), (0, asn1_1.dateToASN1DateTimeInUTC)(expiryDate), new asn1js_1.OctetString({ valueHex: gatewayData })).toBER();
            await expect((0, rsaSigning_1.verify)(signature, gatewayKeyPair.publicKey, expectedPlaintext)).resolves.toBeTrue();
        });
    });
    describe('deserialize', () => {
        test('Malformed values should be refused', async () => {
            await expect(PrivateNodeRegistrationAuthorization_1.PrivateNodeRegistrationAuthorization.deserialize((0, _test_utils_1.arrayBufferFrom)('foo'), gatewayKeyPair.publicKey)).rejects.toEqual(new InvalidMessageError_1.default('Serialization is not a valid PrivateNodeRegistrationAuthorization'));
        });
        test('Sequence should have at least 3 items', async () => {
            const serialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.VisibleString({ value: 'foo' }), new asn1js_1.VisibleString({ value: 'bar' })).toBER();
            await expect(PrivateNodeRegistrationAuthorization_1.PrivateNodeRegistrationAuthorization.deserialize(serialization, gatewayKeyPair.publicKey)).rejects.toEqual(new InvalidMessageError_1.default('Serialization is not a valid PrivateNodeRegistrationAuthorization'));
        });
        test('Expired authorizations should be refused', async () => {
            const oneSecondAgo = new Date();
            oneSecondAgo.setSeconds(-1);
            const authorization = new PrivateNodeRegistrationAuthorization_1.PrivateNodeRegistrationAuthorization(oneSecondAgo, gatewayData);
            const serialization = await authorization.serialize(gatewayKeyPair.privateKey);
            await expect(PrivateNodeRegistrationAuthorization_1.PrivateNodeRegistrationAuthorization.deserialize(serialization, gatewayKeyPair.publicKey)).rejects.toEqual(new InvalidMessageError_1.default('Authorization already expired'));
        });
        test('Invalid signatures should be refused', async () => {
            const tomorrow = (0, moment_1.default)().add(1, 'days').toDate();
            const serialization = (0, asn1_1.makeImplicitlyTaggedSequence)((0, asn1_1.dateToASN1DateTimeInUTC)(tomorrow), new asn1js_1.VisibleString({ value: 'gateway data' }), new asn1js_1.VisibleString({ value: 'invalid signature' })).toBER();
            await expect(PrivateNodeRegistrationAuthorization_1.PrivateNodeRegistrationAuthorization.deserialize(serialization, gatewayKeyPair.publicKey)).rejects.toEqual(new InvalidMessageError_1.default('Authorization signature is invalid'));
        });
        test('Valid values should be accepted', async () => {
            const authorization = new PrivateNodeRegistrationAuthorization_1.PrivateNodeRegistrationAuthorization(expiryDate, gatewayData);
            const serialization = await authorization.serialize(gatewayKeyPair.privateKey);
            const authorizationDeserialized = await PrivateNodeRegistrationAuthorization_1.PrivateNodeRegistrationAuthorization.deserialize(serialization, gatewayKeyPair.publicKey);
            expect(authorizationDeserialized.expiryDate).toEqual(expiryDate);
            expect(authorizationDeserialized.gatewayData).toEqual(gatewayData);
        });
    });
});
//# sourceMappingURL=PrivateNodeRegistrationAuthorization.spec.js.map