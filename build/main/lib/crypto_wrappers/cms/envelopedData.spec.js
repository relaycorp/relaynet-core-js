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
const envelopedData_1 = require("./envelopedData");
const _utils_1 = require("./_utils");
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_RSA_OAEP = '1.2.840.113549.1.1.7';
const OID_RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER = '0.4.0.127.0.17.0.1.0';
const plaintext = (0, _test_utils_1.arrayBufferFrom)('Winter is coming');
// For sessionless tests:
let nodePrivateKey;
let nodeCertificate;
beforeAll(async () => {
    const nodeKeyPair = await (0, keys_1.generateRSAKeyPair)();
    nodePrivateKey = nodeKeyPair.privateKey;
    nodeCertificate = await (0, _test_utils_1.generateStubCert)({
        attributes: { isCA: true },
        issuerPrivateKey: nodePrivateKey,
        subjectPublicKey: nodeKeyPair.publicKey,
    });
});
// For channel session tests:
let bobDhPrivateKey;
const bobSessionKeyId = Buffer.from('bob session key id');
let bobSessionKey;
beforeAll(async () => {
    const bobDhKeyPair = await (0, keys_1.generateECDHKeyPair)();
    bobDhPrivateKey = bobDhKeyPair.privateKey;
    bobSessionKey = { keyId: bobSessionKeyId, publicKey: bobDhKeyPair.publicKey };
});
afterEach(() => {
    jest.restoreAllMocks();
});
describe('EnvelopedData', () => {
    describe('serialize', () => {
        test('EnvelopedData value should be wrapped in ContentInfo', async () => {
            const envelopedData = await envelopedData_1.SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);
            const envelopedDataSerialized = envelopedData.serialize();
            const contentInfo = (0, _test_utils_2.deserializeContentInfo)(envelopedDataSerialized);
            expect(contentInfo.contentType).toEqual(oids_1.CMS_OIDS.ENVELOPED_DATA);
            expect(contentInfo.content).toBeInstanceOf(asn1js.Sequence);
        });
    });
    describe('deserialize', () => {
        test('Non-DER-encoded values should be refused', () => {
            const invalidDer = (0, _test_utils_1.arrayBufferFrom)('nope.jpeg');
            expect(() => envelopedData_1.EnvelopedData.deserialize(invalidDer)).toThrowWithMessage(CMSError_1.default, 'Could not deserialize CMS ContentInfo: Value is not DER-encoded');
        });
        test('Outer value should be a CMS ContentInfo', () => {
            const asn1Value = new asn1js.Integer({ value: 3 });
            const derValue = asn1Value.toBER(false);
            expect(() => envelopedData_1.EnvelopedData.deserialize(derValue)).toThrowWithMessage(CMSError_1.default, /^Could not deserialize CMS ContentInfo: /);
        });
        test('OID of inner value should be that of EnvelopedData', async () => {
            const envelopedData = await envelopedData_1.SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);
            const contentInfo = new pkijs.ContentInfo({
                content: envelopedData.pkijsEnvelopedData.toSchema(),
                contentType: '1.2',
            });
            const contentInfoSerialized = contentInfo.toSchema().toBER(false);
            expect(() => envelopedData_1.EnvelopedData.deserialize(contentInfoSerialized)).toThrowWithMessage(CMSError_1.default, 'ContentInfo does not wrap an EnvelopedData value (got OID 1.2)');
        });
        test('Inner value should be a valid EnvelopedData', async () => {
            const contentInfo = new pkijs.ContentInfo({
                content: new asn1js.Integer({ value: 3 }),
                contentType: oids_1.CMS_OIDS.ENVELOPED_DATA,
            });
            const contentInfoSerialized = contentInfo.toSchema().toBER(false);
            expect(() => envelopedData_1.EnvelopedData.deserialize(contentInfoSerialized)).toThrowWithMessage(CMSError_1.default, /^Invalid EnvelopedData value: /);
        });
        test('An EnvelopedData with zero recipientInfos should be refused', () => {
            const pkijsEnvelopedData = new pkijs.EnvelopedData();
            pkijsEnvelopedData.recipientInfos = [];
            const contentInfo = new pkijs.ContentInfo({
                content: pkijsEnvelopedData.toSchema(),
                contentType: oids_1.CMS_OIDS.ENVELOPED_DATA,
            });
            const contentInfoSerialized = contentInfo.toSchema().toBER(false);
            expect(() => envelopedData_1.EnvelopedData.deserialize(contentInfoSerialized)).toThrowWithMessage(CMSError_1.default, /^Invalid EnvelopedData value:/);
        });
        test('An EnvelopedData with multiple recipientInfos should be refused', async () => {
            const envelopedData = await envelopedData_1.SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);
            envelopedData.pkijsEnvelopedData.addRecipientByCertificate(nodeCertificate.pkijsCertificate, {}, 1);
            const contentInfo = new pkijs.ContentInfo({
                content: envelopedData.pkijsEnvelopedData.toSchema(),
                contentType: oids_1.CMS_OIDS.ENVELOPED_DATA,
            });
            const contentInfoSerialized = contentInfo.toSchema().toBER(false);
            expect(() => envelopedData_1.EnvelopedData.deserialize(contentInfoSerialized)).toThrowWithMessage(CMSError_1.default, 'EnvelopedData must have exactly one RecipientInfo (got 2)');
        });
        test('KeyTransRecipientInfo should result in SessionlessEnvelopedData instance', async () => {
            const originalEnvelopedData = await envelopedData_1.SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);
            const envelopedDataSerialized = originalEnvelopedData.serialize();
            const envelopedData = envelopedData_1.EnvelopedData.deserialize(envelopedDataSerialized);
            expect(envelopedData).toBeInstanceOf(envelopedData_1.SessionlessEnvelopedData);
            (0, _test_utils_1.expectAsn1ValuesToBeEqual)(originalEnvelopedData.pkijsEnvelopedData.toSchema(), envelopedData.pkijsEnvelopedData.toSchema());
        });
        test('A KeyAgreeRecipientInfo should result in a SessionEnvelopedData instance', async () => {
            const { envelopedData } = await envelopedData_1.SessionEnvelopedData.encrypt(plaintext, bobSessionKey);
            const envelopedDataSerialized = envelopedData.serialize();
            const envelopedDataDeserialized = envelopedData_1.EnvelopedData.deserialize(envelopedDataSerialized);
            expect(envelopedDataDeserialized).toBeInstanceOf(envelopedData_1.SessionEnvelopedData);
            (0, _test_utils_1.expectAsn1ValuesToBeEqual)(envelopedDataDeserialized.pkijsEnvelopedData.toSchema(), envelopedData.pkijsEnvelopedData.toSchema());
        });
        test('An unsupported RecipientInfo should be refused', async () => {
            const unsupportedEnvelopedData = await envelopedData_1.SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);
            const unsupportedEnvelopedDataSerialized = unsupportedEnvelopedData.serialize();
            jest
                .spyOn(pkijs.RecipientInfo.prototype, 'fromSchema')
                .mockImplementationOnce(function () {
                this.variant = 3;
            });
            expect(() => envelopedData_1.EnvelopedData.deserialize(unsupportedEnvelopedDataSerialized)).toThrowWithMessage(CMSError_1.default, 'Unsupported RecipientInfo (variant: 3)');
        });
    });
});
describe('SessionlessEnvelopedData', () => {
    describe('encrypt', () => {
        describe('RecipientInfo', () => {
            test('RecipientInfo should be of type KeyTransRecipientInfo', async () => {
                const envelopedData = await envelopedData_1.SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);
                expect(envelopedData.pkijsEnvelopedData.recipientInfos[0].value).toBeInstanceOf(pkijs.KeyTransRecipientInfo);
            });
            test('KeyTransRecipientInfo should use issuerAndSerialNumber choice', async () => {
                const envelopedData = await envelopedData_1.SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);
                const keyTransRecipientInfo = envelopedData.pkijsEnvelopedData.recipientInfos[0].value;
                (0, _utils_1.assertPkiType)(keyTransRecipientInfo, pkijs.KeyTransRecipientInfo, 'keyTransRecipientInfo');
                (0, _utils_1.assertPkiType)(keyTransRecipientInfo.rid, pkijs.IssuerAndSerialNumber, 'keyTransRecipientInfo.rid');
                expect(keyTransRecipientInfo.version).toEqual(0);
                expect(keyTransRecipientInfo.rid).toBeInstanceOf(pkijs.IssuerAndSerialNumber);
                (0, _test_utils_1.expectPkijsValuesToBeEqual)(keyTransRecipientInfo.rid.issuer, nodeCertificate.pkijsCertificate.issuer);
                (0, _test_utils_1.expectAsn1ValuesToBeEqual)(keyTransRecipientInfo.rid.serialNumber, nodeCertificate.pkijsCertificate.serialNumber);
            });
            test('KeyTransRecipientInfo should use RSA-OAEP', async () => {
                const envelopedData = await envelopedData_1.SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);
                const keyTransRecipientInfo = envelopedData.pkijsEnvelopedData.recipientInfos[0].value;
                (0, _utils_1.assertPkiType)(keyTransRecipientInfo, pkijs.KeyTransRecipientInfo, 'keyTransRecipientInfo');
                expect(keyTransRecipientInfo.keyEncryptionAlgorithm.algorithmId).toEqual(OID_RSA_OAEP);
            });
            test('RSA-OAEP should be used with SHA-256', async () => {
                const envelopedData = await envelopedData_1.SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);
                const keyTransRecipientInfo = envelopedData.pkijsEnvelopedData.recipientInfos[0].value;
                (0, _utils_1.assertPkiType)(keyTransRecipientInfo, pkijs.KeyTransRecipientInfo, 'keyTransRecipientInfo');
                const algorithmParams = new pkijs.RSAESOAEPParams({
                    schema: keyTransRecipientInfo.keyEncryptionAlgorithm.algorithmParams,
                });
                expect(algorithmParams.hashAlgorithm.algorithmId).toEqual(OID_SHA256);
            });
        });
        describeEncryptedContentInfoEncryption(async (options) => {
            const envelopedData = await envelopedData_1.SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate, options);
            return envelopedData.serialize();
        });
    });
    describe('decrypt', () => {
        test('Decryption with the wrong private key should fail', async () => {
            const differentCertificate = await (0, _test_utils_1.generateStubCert)();
            const envelopedData = await envelopedData_1.SessionlessEnvelopedData.encrypt(plaintext, differentCertificate);
            expect.hasAssertions();
            try {
                await envelopedData.decrypt(nodePrivateKey);
            }
            catch (error) {
                expect(error).toBeInstanceOf(CMSError_1.default);
                expect(error.message).toStartWith(`Decryption failed: ${error.cause().message}`);
            }
        });
        test('Decryption should succeed with the right private key', async () => {
            const envelopedData = await envelopedData_1.SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);
            const actualPlaintext = await envelopedData.decrypt(nodePrivateKey);
            (0, _test_utils_1.expectArrayBuffersToEqual)(actualPlaintext, plaintext);
        });
    });
    test('getRecipientKeyId() should return the recipient key id', async () => {
        const envelopedData = await envelopedData_1.SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);
        const actualKeyId = envelopedData.getRecipientKeyId();
        expect(actualKeyId).toEqual(nodeCertificate.getSerialNumber());
    });
});
describe('SessionEnvelopedData', () => {
    describe('encrypt', () => {
        test('RecipientInfo should be KeyAgreeRecipientInfo', async () => {
            const { envelopedData } = await envelopedData_1.SessionEnvelopedData.encrypt(plaintext, bobSessionKey);
            const recipientInfo = envelopedData.pkijsEnvelopedData.recipientInfos[0];
            expect(recipientInfo.value).toBeInstanceOf(pkijs.KeyAgreeRecipientInfo);
        });
        test('Result should include generated (EC)DH private key', async () => {
            jest.spyOn(pkijs.EnvelopedData.prototype, 'encrypt');
            const { dhPrivateKey } = await envelopedData_1.SessionEnvelopedData.encrypt(plaintext, bobSessionKey);
            const pkijsEncryptCall = (0, _test_utils_1.getMockContext)(pkijs.EnvelopedData.prototype.encrypt).results[0];
            expect(dhPrivateKey).toBe((await pkijsEncryptCall.value)[0].ecdhPrivateKey);
        });
        test('Generated (EC)DH key id should be output and included in unprotectedAttrs', async () => {
            const { envelopedData, dhKeyId } = await envelopedData_1.SessionEnvelopedData.encrypt(plaintext, bobSessionKey);
            expect(dhKeyId).toBeInstanceOf(ArrayBuffer);
            expect(dhKeyId).toHaveProperty('byteLength', 8);
            expect(envelopedData.pkijsEnvelopedData.unprotectedAttrs).toHaveLength(1);
            const dhKeyIdAttribute = envelopedData.pkijsEnvelopedData.unprotectedAttrs[0];
            expect(dhKeyIdAttribute).toHaveProperty('type', OID_RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER);
            const dhKeyIdAttributeValue = dhKeyIdAttribute.values[0];
            expect(dhKeyIdAttributeValue).toBeInstanceOf(asn1js.OctetString);
            (0, _test_utils_1.expectArrayBuffersToEqual)(dhKeyIdAttributeValue.valueBlock.valueHex, dhKeyId);
        });
        test('Recipient key id should be stored in EnvelopedData', async () => {
            const { envelopedData } = await envelopedData_1.SessionEnvelopedData.encrypt(plaintext, bobSessionKey);
            const keyInfo = envelopedData.pkijsEnvelopedData.recipientInfos[0].value;
            (0, _utils_1.assertPkiType)(keyInfo, pkijs.KeyAgreeRecipientInfo, 'keyInfo');
            const encryptedKey = keyInfo.recipientEncryptedKeys.encryptedKeys[0];
            const subjectKeyIdentifierBlock = encryptedKey.rid.value.subjectKeyIdentifier;
            expect(Buffer.from(subjectKeyIdentifierBlock.valueBlock.valueHex)).toEqual(bobSessionKeyId);
        });
        describeEncryptedContentInfoEncryption(async (options) => {
            const { envelopedData } = await envelopedData_1.SessionEnvelopedData.encrypt(plaintext, bobSessionKey, options);
            return envelopedData.serialize();
        });
    });
    describe('getOriginatorKey', () => {
        let envelopedData;
        beforeEach(async () => {
            const encryptionResult = await envelopedData_1.SessionEnvelopedData.encrypt(plaintext, bobSessionKey);
            envelopedData = encryptionResult.envelopedData;
        });
        describe('keyId', () => {
            test('Originator DH public key id should be returned', async () => {
                const { keyId } = await envelopedData.getOriginatorKey();
                const unprotectedAttrs = envelopedData.pkijsEnvelopedData
                    .unprotectedAttrs;
                const dhKeyIdAttribute = unprotectedAttrs[0];
                expect(keyId).toEqual(Buffer.from(dhKeyIdAttribute.values[0].valueBlock.valueHex));
            });
            test('Call should fail if unprotectedAttrs is missing', async () => {
                envelopedData.pkijsEnvelopedData.unprotectedAttrs = undefined;
                await expect(envelopedData.getOriginatorKey()).rejects.toEqual(new CMSError_1.default('unprotectedAttrs must be present when using channel session'));
            });
            test('Call should fail if unprotectedAttrs is present but empty', async () => {
                envelopedData.pkijsEnvelopedData.unprotectedAttrs = [];
                await expect(envelopedData.getOriginatorKey()).rejects.toEqual(new CMSError_1.default('unprotectedAttrs must be present when using channel session'));
            });
            test('Call should fail if originator key id is missing', async () => {
                const otherAttribute = new pkijs.Attribute({
                    type: '1.2.3.4',
                    values: [new asn1js.Integer({ value: 2 })],
                });
                envelopedData.pkijsEnvelopedData.unprotectedAttrs = [otherAttribute];
                await expect(envelopedData.getOriginatorKey()).rejects.toEqual(new CMSError_1.default('unprotectedAttrs does not contain originator key id'));
            });
            test('Call should fail if attribute for originator key id is empty', async () => {
                const invalidAttribute = new pkijs.Attribute({
                    type: OID_RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
                    values: [],
                });
                envelopedData.pkijsEnvelopedData.unprotectedAttrs = [invalidAttribute];
                await expect(envelopedData.getOriginatorKey()).rejects.toEqual(new CMSError_1.default('Originator key id attribute must have exactly one value (got 0)'));
            });
            test('Call should fail if attribute for originator key id is multi-valued', async () => {
                const invalidAttribute = new pkijs.Attribute({
                    type: OID_RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
                    values: [new asn1js.Integer({ value: 1 }), new asn1js.Integer({ value: 2 })],
                });
                envelopedData.pkijsEnvelopedData.unprotectedAttrs = [invalidAttribute];
                await expect(envelopedData.getOriginatorKey()).rejects.toEqual(new CMSError_1.default('Originator key id attribute must have exactly one value (got 2)'));
            });
        });
        describe('publicKey', () => {
            test('Originator DH public key should be returned if it is valid', async () => {
                const { publicKey } = await envelopedData.getOriginatorKey();
                const recipientInfo = envelopedData.pkijsEnvelopedData.recipientInfos[0];
                (0, _utils_1.assertPkiType)(recipientInfo, pkijs.RecipientInfo, 'recipientInfo');
                (0, _utils_1.assertPkiType)(recipientInfo.value, pkijs.KeyAgreeRecipientInfo, 'recipientInfo.value');
                const expectedPublicKeyDer = recipientInfo.value.originator.value.toSchema().toBER(false);
                expect(Buffer.from(expectedPublicKeyDer)).toEqual(await (0, keys_1.derSerializePublicKey)(publicKey));
            });
            test('Call should fail if RecipientInfo is not KeyAgreeRecipientInfo', async () => {
                envelopedData.pkijsEnvelopedData.recipientInfos[0].variant = 3;
                await expect(envelopedData.getOriginatorKey()).rejects.toEqual(new CMSError_1.default('Expected KeyAgreeRecipientInfo (got variant: 3)'));
            });
        });
    });
    test('getRecipientKeyId() should return the recipient key id', async () => {
        const { envelopedData } = await envelopedData_1.SessionEnvelopedData.encrypt(plaintext, bobSessionKey);
        const actualKeyId = envelopedData.getRecipientKeyId();
        expect(actualKeyId).toEqual(bobSessionKeyId);
    });
    describe('decrypt', () => {
        test('Decryption with the wrong private key should fail', async () => {
            const differentDhKeyPair = await (0, keys_1.generateECDHKeyPair)();
            const { envelopedData } = await envelopedData_1.SessionEnvelopedData.encrypt(plaintext, bobSessionKey);
            expect.hasAssertions();
            try {
                await envelopedData.decrypt(differentDhKeyPair.privateKey);
            }
            catch (error) {
                expect(error).toBeInstanceOf(CMSError_1.default);
                expect(error.message).toStartWith(`Decryption failed: ${error.cause().message}`);
            }
        });
        test('Decryption should succeed with the right private key', async () => {
            const { envelopedData } = await envelopedData_1.SessionEnvelopedData.encrypt(plaintext, bobSessionKey);
            const decryptedPlaintext = await envelopedData.decrypt(bobDhPrivateKey);
            (0, _test_utils_1.expectArrayBuffersToEqual)(decryptedPlaintext, plaintext);
        });
    });
});
function describeEncryptedContentInfoEncryption(encryptFunc) {
    describe('EncryptedContentInfo', () => {
        test('AES-CBC-128 should be used by default', async () => {
            const envelopedDataSerialized = await encryptFunc();
            const envelopedData = deserializeEnvelopedData(envelopedDataSerialized);
            expect(envelopedData.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId).toEqual(_test_utils_1.CRYPTO_OIDS.AES_CBC_128);
        });
        test.each([
            [192, _test_utils_1.CRYPTO_OIDS.AES_CBC_192],
            [256, _test_utils_1.CRYPTO_OIDS.AES_CBC_256],
        ])('AES-CBC-%s should also be supported', async (aesKeySize, expectedOid) => {
            const envelopedDataSerialized = await encryptFunc({ aesKeySize: aesKeySize });
            const envelopedData = deserializeEnvelopedData(envelopedDataSerialized);
            expect(envelopedData.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId).toEqual(expectedOid);
        });
        test('Key sizes other than 128, 192 and 256 should be refused', async () => {
            await expect(encryptFunc({ aesKeySize: 512 })).rejects.toEqual(new CMSError_1.default('Invalid AES key size (512)'));
        });
    });
}
function deserializeEnvelopedData(contentInfoDer) {
    const contentInfo = (0, _test_utils_2.deserializeContentInfo)(contentInfoDer);
    return new pkijs.EnvelopedData({ schema: contentInfo.content });
}
//# sourceMappingURL=envelopedData.spec.js.map