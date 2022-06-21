"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const asn1js_1 = require("asn1js");
const _test_utils_1 = require("../_test_utils");
const asn1_1 = require("../asn1");
const CertificationPath_1 = require("../pki/CertificationPath");
const CertificateRotation_1 = require("./CertificateRotation");
const InvalidMessageError_1 = __importDefault(require("./InvalidMessageError"));
describe('CertificateRotation', () => {
    let subjectCertificate;
    let issuerCertificate;
    let certificationPath;
    beforeAll(async () => {
        subjectCertificate = await (0, _test_utils_1.generateStubCert)();
        issuerCertificate = await (0, _test_utils_1.generateStubCert)();
        certificationPath = new CertificationPath_1.CertificationPath(subjectCertificate, [issuerCertificate]);
    });
    describe('serialize', () => {
        test('Serialization should start with format signature', async () => {
            const rotation = new CertificateRotation_1.CertificateRotation(certificationPath);
            const serialization = rotation.serialize();
            const expectedFormatSignature = Buffer.concat([
                Buffer.from('Relaynet'),
                Buffer.from([0x10, 0x00]),
            ]);
            expect(Buffer.from(serialization).slice(0, 10)).toEqual(expectedFormatSignature);
        });
        test('Serialization should contain CertificationPath', async () => {
            const rotation = new CertificateRotation_1.CertificateRotation(certificationPath);
            const pathSerialized = rotation.serialize().slice(10);
            expect(pathSerialized).toEqual(certificationPath.serialize());
        });
    });
    describe('deserialize', () => {
        test('Serialization should start with format signature', () => {
            const invalidSerialization = (0, _test_utils_1.arrayBufferFrom)('RelaynetA0');
            expect(() => CertificateRotation_1.CertificateRotation.deserialize(invalidSerialization)).toThrowWithMessage(InvalidMessageError_1.default, 'Format signature should be that of a CertificateRotation');
        });
        test('Serialization should contain a well-formed CertificationPath', async () => {
            const invalidSerialization = (0, _test_utils_1.arrayBufferFrom)([
                ...CertificateRotation_1.CERTIFICATE_ROTATION_FORMAT_SIGNATURE,
                ...Buffer.from((0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.VisibleString()).toBER(false)),
            ]);
            const error = (0, _test_utils_1.catchError)(() => CertificateRotation_1.CertificateRotation.deserialize(invalidSerialization), InvalidMessageError_1.default);
            expect(error.message).toStartWith('CertificationPath is malformed');
            expect(error.cause()).toBeInstanceOf(InvalidMessageError_1.default);
        });
        test('A new instance should be returned if serialization is valid', async () => {
            const rotation = new CertificateRotation_1.CertificateRotation(certificationPath);
            const serialization = rotation.serialize();
            const rotationDeserialized = CertificateRotation_1.CertificateRotation.deserialize(serialization);
            expect(rotationDeserialized.certificationPath.leafCertificate.isEqual(subjectCertificate)).toBeTrue();
            expect(rotationDeserialized.certificationPath.certificateAuthorities).toHaveLength(1);
            expect(rotationDeserialized.certificationPath.certificateAuthorities[0].isEqual(issuerCertificate));
        });
    });
});
//# sourceMappingURL=CertificateRotation.spec.js.map