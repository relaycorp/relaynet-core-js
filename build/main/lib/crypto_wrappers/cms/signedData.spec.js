"use strict";
// tslint:disable:no-object-mutation
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
const pkijs = __importStar(require("pkijs"));
const _test_utils_1 = require("../../_test_utils");
const oids_1 = require("../../oids");
const keys_1 = require("../keys");
const _test_utils_2 = require("./_test_utils");
const CMSError_1 = __importDefault(require("./CMSError"));
const signedData_1 = require("./signedData");
const plaintext = (0, _test_utils_1.arrayBufferFrom)('Winter is coming');
let keyPair;
let certificate;
beforeAll(async () => {
    keyPair = await (0, keys_1.generateRSAKeyPair)();
    certificate = await (0, _test_utils_1.generateStubCert)({
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
    });
});
afterEach(() => {
    jest.restoreAllMocks();
});
describe('sign', () => {
    test('SignedData version should be 1', async () => {
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
        expect(signedData.pkijsSignedData).toHaveProperty('version', 1);
    });
    describe('SignerInfo', () => {
        test('There should only be one SignerInfo', async () => {
            const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
            expect(signedData.pkijsSignedData.signerInfos).toHaveLength(1);
            expect(signedData.pkijsSignedData.signerInfos[0]).toBeInstanceOf(pkijs.SignerInfo);
        });
        test('Version should be 1', async () => {
            const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
            expect(signedData.pkijsSignedData.signerInfos[0]).toHaveProperty('version', 1);
        });
        test('SignerIdentifier should be IssuerAndSerialNumber', async () => {
            const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
            const signerInfo = signedData.pkijsSignedData.signerInfos[0];
            expect(signerInfo.sid).toBeInstanceOf(pkijs.IssuerAndSerialNumber);
            (0, _test_utils_1.expectPkijsValuesToBeEqual)(signerInfo.sid.issuer, certificate.pkijsCertificate.issuer);
            (0, _test_utils_1.expectAsn1ValuesToBeEqual)(signerInfo.sid.serialNumber, certificate.pkijsCertificate.serialNumber);
        });
        describe('SignedAttributes', () => {
            test('Signed attributes should be present', async () => {
                const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
                const signerInfo = signedData.pkijsSignedData.signerInfos[0];
                expect(signerInfo.signedAttrs).toBeInstanceOf(pkijs.SignedAndUnsignedAttributes);
                expect(signerInfo.signedAttrs).toHaveProperty('type', 0);
            });
            test('Content type attribute should be set to CMS Data', async () => {
                const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
                const contentTypeAttribute = getSignerInfoAttribute(signedData.pkijsSignedData.signerInfos[0], oids_1.CMS_OIDS.ATTR_CONTENT_TYPE);
                // @ts-ignore
                expect(contentTypeAttribute.values).toHaveLength(1);
                expect(
                // @ts-ignore
                contentTypeAttribute.values[0].valueBlock.toString()).toEqual(oids_1.CMS_OIDS.DATA);
            });
            test('Plaintext digest should be present', async () => {
                const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
                const digestAttribute = getSignerInfoAttribute(signedData.pkijsSignedData.signerInfos[0], oids_1.CMS_OIDS.ATTR_DIGEST);
                // @ts-ignore
                expect(digestAttribute.values).toHaveLength(1);
                expect(
                // @ts-ignore
                digestAttribute.values[0].valueBlock.valueHex).toBeTruthy();
            });
        });
    });
    describe('Attached certificates', () => {
        test('The signer certificate should be attached', async () => {
            const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
            expect(signedData.pkijsSignedData.certificates).toHaveLength(1);
            (0, _test_utils_1.expectPkijsValuesToBeEqual)(signedData.pkijsSignedData.certificates[0], certificate.pkijsCertificate);
        });
        test('CA certificate chain should optionally be attached', async () => {
            const rootCaCertificate = await (0, _test_utils_1.generateStubCert)();
            const intermediateCaCertificate = await (0, _test_utils_1.generateStubCert)();
            const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate, [
                intermediateCaCertificate,
                rootCaCertificate,
            ]);
            expect(signedData.pkijsSignedData.certificates).toHaveLength(3);
            const attachedCertificates = signedData.pkijsSignedData
                .certificates;
            (0, _test_utils_1.expectPkijsValuesToBeEqual)(attachedCertificates[0], certificate.pkijsCertificate);
            (0, _test_utils_1.expectPkijsValuesToBeEqual)(attachedCertificates[1], intermediateCaCertificate.pkijsCertificate);
            (0, _test_utils_1.expectPkijsValuesToBeEqual)(attachedCertificates[2], rootCaCertificate.pkijsCertificate);
        });
    });
    describe('Hashing', () => {
        test('SHA-256 should be used by default', async () => {
            const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
            const digestAttribute = getSignerInfoAttribute(signedData.pkijsSignedData.signerInfos[0], oids_1.CMS_OIDS.ATTR_DIGEST);
            expect(
            // @ts-ignore
            Buffer.from(digestAttribute.values[0].valueBlock.valueHex).toString('hex')).toEqual((0, _test_utils_1.sha256Hex)(plaintext));
        });
        test.each(['SHA-384', 'SHA-512'])('%s should be supported', async (hashingAlgorithmName) => {
            const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate, [], {
                hashingAlgorithmName,
            });
            const digestAttribute = getSignerInfoAttribute(signedData.pkijsSignedData.signerInfos[0], oids_1.CMS_OIDS.ATTR_DIGEST);
            const algorithmNameNodejs = hashingAlgorithmName.toLowerCase().replace('-', '');
            const digest = digestAttribute.values[0].valueBlock.valueHex;
            expect(Buffer.from(digest).toString('hex')).toEqual((0, _test_utils_1.calculateDigestHex)(algorithmNameNodejs, plaintext));
        });
        test('SHA-1 should not be a valid hashing function', async () => {
            expect.hasAssertions();
            try {
                await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate, [], {
                    hashingAlgorithmName: 'SHA-1',
                });
            }
            catch (error) {
                expect(error).toBeInstanceOf(CMSError_1.default);
                expect(error.message).toEqual('SHA-1 is disallowed by RS-018');
            }
        });
    });
    describe('Plaintext', () => {
        test('Plaintext should be encapsulated by default', async () => {
            const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
            const encapContentInfo = signedData.pkijsSignedData.encapContentInfo;
            expect(encapContentInfo).toBeInstanceOf(pkijs.EncapsulatedContentInfo);
            expect(encapContentInfo).toHaveProperty('eContentType', oids_1.CMS_OIDS.DATA);
            expect(encapContentInfo).toHaveProperty('eContent');
            if (!encapContentInfo.eContent) {
                throw new Error('encapContentInfo.eContent is empty');
            }
            const plaintextOctetString = encapContentInfo.eContent.valueBlock
                .value[0];
            (0, _test_utils_1.expectArrayBuffersToEqual)(plaintextOctetString.valueBlock.valueHexView.slice().buffer, plaintext);
        });
        test('Content should not be encapsulated if requested', async () => {
            const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate, undefined, { encapsulatePlaintext: false });
            const encapContentInfo = signedData.pkijsSignedData.encapContentInfo;
            expect(encapContentInfo).toBeInstanceOf(pkijs.EncapsulatedContentInfo);
            expect(encapContentInfo).toHaveProperty('eContentType', oids_1.CMS_OIDS.DATA);
            expect(encapContentInfo).toHaveProperty('eContent', undefined);
        });
    });
});
describe('serialize', () => {
    test('SignedData value should be wrapped in ContentInfo', async () => {
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
        const signedDataSerialized = signedData.serialize();
        const contentInfo = (0, _test_utils_2.deserializeContentInfo)(signedDataSerialized);
        expect(contentInfo.content.toBER(false)).toEqual(signedData.pkijsSignedData.toSchema(true).toBER(false));
    });
    test('ContentInfo OID should match that of SignedData values', async () => {
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
        const signedDataSerialized = signedData.serialize();
        const contentInfo = (0, _test_utils_2.deserializeContentInfo)(signedDataSerialized);
        expect(contentInfo.contentType).toEqual(oids_1.CMS_OIDS.SIGNED_DATA);
    });
});
describe('deserialize', () => {
    test('A non-DER-encoded value should be refused', async () => {
        const invalidSignature = (0, _test_utils_1.arrayBufferFrom)('nope.jpeg');
        expect(() => signedData_1.SignedData.deserialize(invalidSignature)).toThrowWithMessage(CMSError_1.default, 'Could not deserialize CMS ContentInfo: Value is not DER-encoded');
    });
    test('ContentInfo wrapper should be required', async () => {
        const invalidSignature = new asn1js.Sequence().toBER(false);
        expect(() => signedData_1.SignedData.deserialize(invalidSignature)).toThrowWithMessage(CMSError_1.default, 'Could not deserialize CMS ContentInfo: ' +
            "Object's schema was not verified against input data for ContentInfo");
    });
    test('Malformed SignedData values should be refused', async () => {
        const invalidSignature = (0, _test_utils_2.serializeContentInfo)(new asn1js.Sequence(), '1.2.3.4');
        await expect(() => signedData_1.SignedData.deserialize(invalidSignature)).toThrowWithMessage(CMSError_1.default, 'SignedData value is malformed');
    });
    test('Well-formed SignedData values should be deserialized', async () => {
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
        const signedDataSerialized = signedData.serialize();
        const signedDataDeserialized = signedData_1.SignedData.deserialize(signedDataSerialized);
        expect(signedDataDeserialized.serialize()).toEqual(signedData.serialize());
    });
});
describe('verify', () => {
    test('Value should be refused if plaintext is not encapsulated or specified', async () => {
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate, undefined, {
            encapsulatePlaintext: false,
        });
        await expect(signedData.verify()).rejects.toMatchObject({
            message: 'Plaintext should be encapsulated or explicitly set',
        });
    });
    test('Expected plaintext should be refused if one is already encapsulated', async () => {
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
        await expect(signedData.verify(plaintext)).rejects.toEqual(new CMSError_1.default('No specific plaintext should be expected because one is already encapsulated'));
    });
    test('Invalid signature without encapsulated plaintext should be rejected', async () => {
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate, undefined, {
            encapsulatePlaintext: false,
        });
        const differentPlaintext = (0, _test_utils_1.arrayBufferFrom)('this is an invalid plaintext');
        await expect(signedData.verify(differentPlaintext)).rejects.toBeInstanceOf(CMSError_1.default);
    });
    test('Invalid signature with encapsulated plaintext should be rejected', async () => {
        // Let's tamper with the payload
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
        const differentPlaintext = (0, _test_utils_1.arrayBufferFrom)('Different');
        // tslint:disable-next-line:no-object-mutation
        signedData.pkijsSignedData.encapContentInfo = new pkijs.EncapsulatedContentInfo({
            eContent: new asn1js.OctetString({ valueHex: differentPlaintext }),
            eContentType: oids_1.CMS_OIDS.DATA,
        });
        await expect(signedData.verify()).rejects.toBeInstanceOf(CMSError_1.default);
    });
    test('Valid signature without encapsulated plaintext should be accepted', async () => {
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate, undefined, {
            encapsulatePlaintext: false,
        });
        await signedData.verify(plaintext);
    });
    test('Valid signature with encapsulated plaintext should be accepted', async () => {
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
        await signedData.verify();
    });
});
describe('plaintext', () => {
    test('Nothing should be output if plaintext is absent', async () => {
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
        // @ts-ignore
        // tslint:disable-next-line:no-delete
        delete signedData.pkijsSignedData.encapContentInfo.eContent;
        await expect(signedData.plaintext).toBeNull();
    });
    test('Plaintext should be output if present', async () => {
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
        expect(signedData.plaintext).toEqual(plaintext);
    });
    test('Large plaintexts chunked by PKI.js should be put back together', async () => {
        const largePlaintext = (0, _test_utils_1.arrayBufferFrom)('a'.repeat(2 ** 20));
        const signedData = await signedData_1.SignedData.sign(largePlaintext, keyPair.privateKey, certificate);
        expect(signedData.plaintext).toEqual(largePlaintext);
    });
});
describe('signerCertificate', () => {
    test('Nothing should be output if there are no SignerInfo values', async () => {
        const signerCertificate = await (0, _test_utils_1.generateStubCert)({
            issuerPrivateKey: keyPair.privateKey,
            subjectPublicKey: keyPair.publicKey,
        });
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, signerCertificate);
        signedData.pkijsSignedData.signerInfos.pop();
        expect(signedData.signerCertificate).toBeNull();
    });
    test('Certificate with same issuer but different SN should be ignored', async () => {
        const signerCertificate = await (0, _test_utils_1.generateStubCert)({
            issuerPrivateKey: keyPair.privateKey,
            subjectPublicKey: keyPair.publicKey,
        });
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, signerCertificate);
        signedData.pkijsSignedData.signerInfos.forEach((signerInfo) => {
            signerInfo.sid.serialNumber = new asn1js.Integer({
                value: -1,
            });
        });
        expect(signedData.signerCertificate).toBeNull();
    });
    test('Certificate with same SN but different issuer should be ignored', async () => {
        const signerCertificate = await (0, _test_utils_1.generateStubCert)({
            issuerPrivateKey: keyPair.privateKey,
            subjectPublicKey: keyPair.publicKey,
        });
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, signerCertificate);
        signedData.pkijsSignedData.signerInfos.forEach((si) => {
            si.sid.issuer = new pkijs.RelativeDistinguishedNames();
        });
        expect(signedData.signerCertificate).toBeNull();
    });
    test('Certificate with same SN and issuer should be output', async () => {
        const signedData = await signedData_1.SignedData.sign(plaintext, keyPair.privateKey, certificate);
        expect(signedData.signerCertificate?.isEqual(certificate)).toBeTrue();
    });
});
describe('certificates', () => {
    test('Attached CA certificates should be output', async () => {
        const rootCaKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const rootCaCertificate = await (0, _test_utils_1.generateStubCert)({
            attributes: { isCA: true },
            subjectPublicKey: rootCaKeyPair.publicKey,
        });
        const intermediateCaKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const intermediateCaCertificate = await (0, _test_utils_1.generateStubCert)({
            attributes: { isCA: true },
            issuerCertificate: rootCaCertificate,
            issuerPrivateKey: rootCaKeyPair.privateKey,
            subjectPublicKey: intermediateCaKeyPair.publicKey,
        });
        const signerKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const signerCertificate = await (0, _test_utils_1.generateStubCert)({
            issuerCertificate: intermediateCaCertificate,
            issuerPrivateKey: intermediateCaKeyPair.privateKey,
            subjectPublicKey: signerKeyPair.publicKey,
        });
        const signedData = await signedData_1.SignedData.sign(plaintext, signerKeyPair.privateKey, signerCertificate, [intermediateCaCertificate, rootCaCertificate]);
        const certificates = Array.from(signedData.certificates);
        expect(certificates.filter((c) => c.isEqual(rootCaCertificate))).toHaveLength(1);
        expect(certificates.filter((c) => c.isEqual(intermediateCaCertificate))).toHaveLength(1);
        expect(certificates.filter((c) => c.isEqual(signerCertificate))).toHaveLength(1);
    });
});
function getSignerInfoAttribute(signerInfo, attributeOid) {
    const attributes = signerInfo.signedAttrs.attributes;
    const matchingAttrs = attributes.filter((a) => a.type === attributeOid);
    expect(matchingAttrs).toHaveLength(1);
    return matchingAttrs[0];
}
//# sourceMappingURL=signedData.spec.js.map