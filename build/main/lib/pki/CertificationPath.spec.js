"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const asn1js_1 = require("asn1js");
const date_fns_1 = require("date-fns");
const _test_utils_1 = require("../_test_utils");
const asn1_1 = require("../asn1");
const _utils_1 = require("../crypto_wrappers/_utils");
const keys_1 = require("../crypto_wrappers/keys");
const InvalidMessageError_1 = __importDefault(require("../messages/InvalidMessageError"));
const CertificationPath_1 = require("./CertificationPath");
const issuance_1 = require("./issuance");
let subjectCertificate;
let issuerCertificate;
beforeAll(async () => {
    const issuerKeyPair = await (0, keys_1.generateRSAKeyPair)();
    issuerCertificate = await (0, issuance_1.issueGatewayCertificate)({
        subjectPublicKey: issuerKeyPair.publicKey,
        issuerPrivateKey: issuerKeyPair.privateKey,
        validityEndDate: (0, date_fns_1.addDays)(new Date(), 1),
    });
    const subjectKeyPair = await (0, keys_1.generateRSAKeyPair)();
    subjectCertificate = await (0, issuance_1.issueGatewayCertificate)({
        issuerCertificate,
        issuerPrivateKey: issuerKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
        validityEndDate: issuerCertificate.expiryDate,
    });
});
describe('serialize', () => {
    test('Leaf certificate should be serialized', () => {
        const path = new CertificationPath_1.CertificationPath(subjectCertificate, [issuerCertificate]);
        const serialization = path.serialize();
        const pathDeserialized = (0, _utils_1.derDeserialize)(serialization);
        const leafCertificateASN1 = pathDeserialized.valueBlock.value[0];
        (0, _test_utils_1.expectArrayBuffersToEqual)(leafCertificateASN1.valueBlock.toBER(), subjectCertificate.serialize());
    });
    test('Chain should be serialized', () => {
        const path = new CertificationPath_1.CertificationPath(subjectCertificate, [issuerCertificate]);
        const serialization = path.serialize();
        const pathDeserialized = (0, _utils_1.derDeserialize)(serialization);
        const casASN1 = pathDeserialized.valueBlock.value[1];
        expect(casASN1).toBeInstanceOf(asn1js_1.Constructed);
        expect(casASN1.valueBlock.value).toHaveLength(1);
        const caASN1 = casASN1.valueBlock.value[0];
        (0, _test_utils_1.expectArrayBuffersToEqual)(caASN1.valueBlock.toBER(), issuerCertificate.serialize());
    });
});
describe('deserialize', () => {
    test('Serialization should contain a sequence of a least 2 items', async () => {
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString()).toBER(false);
        expect(() => CertificationPath_1.CertificationPath.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Serialization did not meet structure of a CertificationPath');
    });
    test('Malformed subject certificate should be refused', async () => {
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.VisibleString({ value: 'This is supposed to be a cert' }), new asn1js_1.Set()).toBER(false);
        expect(() => CertificationPath_1.CertificationPath.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Leaf certificate is malformed');
    });
    test('Malformed chain should be refused', async () => {
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: subjectCertificate.serialize() }), new asn1js_1.Integer({ value: 42 })).toBER(false);
        expect(() => CertificationPath_1.CertificationPath.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Serialization did not meet structure of a CertificationPath');
    });
    test('Malformed chain certificate should be refused', async () => {
        const invalidSerialization = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: subjectCertificate.serialize() }), (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.VisibleString({ value: 'This is a "certificate" ;-)' }))).toBER(false);
        expect(() => CertificationPath_1.CertificationPath.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Certificate authorities contain malformed certificate');
    });
    test('A new instance should be returned if serialization is valid', async () => {
        const rotation = new CertificationPath_1.CertificationPath(subjectCertificate, [issuerCertificate]);
        const serialization = rotation.serialize();
        const rotationDeserialized = CertificationPath_1.CertificationPath.deserialize(serialization);
        expect(rotationDeserialized.leafCertificate.isEqual(subjectCertificate)).toBeTrue();
        expect(rotationDeserialized.certificateAuthorities).toHaveLength(1);
        expect(rotationDeserialized.certificateAuthorities[0].isEqual(issuerCertificate));
    });
});
//# sourceMappingURL=CertificationPath.spec.js.map