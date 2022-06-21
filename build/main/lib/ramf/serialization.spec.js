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
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const jestDateMock = __importStar(require("jest-date-mock"));
const moment_1 = __importDefault(require("moment"));
const smart_buffer_1 = require("smart-buffer");
const _test_utils_1 = require("../_test_utils");
const asn1_1 = require("../asn1");
const _utils_1 = require("../crypto_wrappers/_utils");
const cmsSignedData = __importStar(require("../crypto_wrappers/cms/signedData"));
const keys_1 = require("../crypto_wrappers/keys");
const _test_utils_2 = require("./_test_utils");
const RAMFSyntaxError_1 = __importDefault(require("./RAMFSyntaxError"));
const RAMFValidationError_1 = __importDefault(require("./RAMFValidationError"));
const serialization_1 = require("./serialization");
const PAYLOAD = Buffer.from('Hi');
const MAX_PAYLOAD_LENGTH = 2 ** 23 - 1;
const MAX_TTL = 15552000;
const NOW = new Date();
// There should be tests covering rounding when there are milliseconds
NOW.setMilliseconds(0);
const stubConcreteMessageTypeOctet = 0x44;
const stubConcreteMessageVersionOctet = 0x2;
const mockStubUuid4 = '56e95d8a-6be2-4020-bb36-5dd0da36c181';
jest.mock('uuid4', () => {
    return {
        __esModule: true,
        default: jest.fn().mockImplementation(() => mockStubUuid4),
    };
});
afterEach(() => {
    jest.restoreAllMocks();
    jestDateMock.clear();
});
describe('MessageSerializer', () => {
    const RECIPIENT_ADDRESS = '0123456789';
    let SENDER_PRIVATE_KEY;
    let SENDER_CERTIFICATE;
    beforeAll(async () => {
        const yesterday = new Date(NOW);
        yesterday.setDate(yesterday.getDate() - 1);
        const tomorrow = new Date(NOW);
        tomorrow.setDate(tomorrow.getDate() + 1);
        const certificateAttributes = { validityStartDate: yesterday, validityEndDate: tomorrow };
        const senderKeyPair = await (0, keys_1.generateRSAKeyPair)();
        SENDER_PRIVATE_KEY = senderKeyPair.privateKey;
        SENDER_CERTIFICATE = await (0, _test_utils_1.generateStubCert)({
            attributes: certificateAttributes,
            subjectPublicKey: senderKeyPair.publicKey,
        });
    });
    beforeEach(() => {
        jestDateMock.advanceTo(NOW);
    });
    describe('serialize', () => {
        describe('Format signature', () => {
            let stubMessage;
            beforeAll(() => {
                stubMessage = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
            });
            test('The ASCII string "Relaynet" should be at the start', async () => {
                const messageSerialized = await (0, serialization_1.serialize)(stubMessage, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                const formatSignature = parseFormatSignature(messageSerialized);
                expect(formatSignature).toHaveProperty('magic', 'Relaynet');
            });
            test('The concrete message type should be represented with an octet', async () => {
                const messageSerialized = await (0, serialization_1.serialize)(stubMessage, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                const formatSignature = parseFormatSignature(messageSerialized);
                expect(formatSignature).toHaveProperty('concreteMessageType', stubConcreteMessageTypeOctet);
            });
            test('The concrete message version should be at the end', async () => {
                const messageSerialized = await (0, serialization_1.serialize)(stubMessage, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                const formatSignature = parseFormatSignature(messageSerialized);
                expect(formatSignature).toHaveProperty('concreteMessageVersion', stubConcreteMessageVersionOctet);
            });
        });
        describe('SignedData', () => {
            let senderCaCertificateChain;
            let cmsSignArgs;
            beforeAll(async () => {
                senderCaCertificateChain = [await (0, _test_utils_1.generateStubCert)()];
                const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
                    senderCaCertificateChain,
                });
                jest.spyOn(cmsSignedData, 'sign');
                await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                expect(cmsSignedData.sign).toBeCalledTimes(1);
                // @ts-ignore
                cmsSignArgs = cmsSignedData.sign.mock.calls[0];
            });
            test('The sender private key should be used to generate signature', () => {
                const actualSenderPrivateKey = cmsSignArgs[1];
                expect(actualSenderPrivateKey).toBe(SENDER_PRIVATE_KEY);
            });
            test('The sender certificate should be used to generate signature', () => {
                const actualSenderCertificate = cmsSignArgs[2];
                expect(actualSenderCertificate).toBe(SENDER_CERTIFICATE);
            });
            test('Sender certificate chain should be attached', () => {
                const attachedCertificates = cmsSignArgs[3];
                expect(attachedCertificates).toHaveLength(senderCaCertificateChain.length);
                for (const cert of senderCaCertificateChain) {
                    expect(attachedCertificates).toContain(cert);
                }
            });
            test('SHA-256 should be used by default', () => {
                const signatureOptions = cmsSignArgs[4];
                expect(signatureOptions).toBe(undefined);
            });
            test.each(['SHA-384', 'SHA-512'])('%s should also be supported', async (hashingAlgorithmName) => {
                const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
                jest.spyOn(cmsSignedData, 'sign');
                await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY, {
                    hashingAlgorithmName,
                });
                expect(cmsSignedData.sign).toBeCalledTimes(1);
                // @ts-ignore
                const signatureArgs = cmsSignedData.sign.mock.calls[0];
                expect(signatureArgs[4]).toEqual({ hashingAlgorithmName });
            });
        });
        describe('Fields', () => {
            test('Fields should be contained in SignedData value', async () => {
                const stubMessage = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
                const messageSerialized = await (0, serialization_1.serialize)(stubMessage, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                await deserializeFields(messageSerialized);
            });
            test('Fields should be serialized as a 5-item ASN.1 sequence', async () => {
                const stubMessage = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
                const messageSerialized = await (0, serialization_1.serialize)(stubMessage, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                const fields = await deserializeFields(messageSerialized);
                expect(fields).toBeInstanceOf(asn1js.Sequence);
                expect(fields.valueBlock.value).toHaveLength(5);
            });
            describe('Recipient address', () => {
                test('Address should be the first item', async () => {
                    const stubMessage = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
                    const messageSerialized = await (0, serialization_1.serialize)(stubMessage, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                    const fields = await deserializeFields(messageSerialized);
                    const addressDeserialized = (0, _test_utils_1.getAsn1SequenceItem)(fields, 0);
                    expect(addressDeserialized.valueBlock.valueHex).toEqual((0, _test_utils_1.arrayBufferFrom)(RECIPIENT_ADDRESS));
                });
                test('Address should not span more than 1024 characters', async () => {
                    const invalidAddress = 'a'.repeat(1025);
                    const stubMessage = new _test_utils_2.StubMessage(invalidAddress, SENDER_CERTIFICATE, PAYLOAD);
                    await expect((0, serialization_1.serialize)(stubMessage, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY)).rejects.toEqual(new RAMFSyntaxError_1.default('Recipient address should not span more than 1024 characters (got 1025)'));
                });
            });
            describe('Message id', () => {
                test('Id should be the second item', async () => {
                    const idLength = 64;
                    const id = 'a'.repeat(idLength);
                    const stubMessage = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
                        id,
                    });
                    const messageSerialized = await (0, serialization_1.serialize)(stubMessage, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                    const fields = await deserializeFields(messageSerialized);
                    const idField = (0, _test_utils_1.getAsn1SequenceItem)(fields, 1);
                    expect(idField.valueBlock.valueHex).toEqual((0, _test_utils_1.arrayBufferFrom)(stubMessage.id));
                });
                test('Ids longer than 64 characters should be refused', async () => {
                    const id = 'a'.repeat(65);
                    const stubMessage = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
                        id,
                    });
                    await expect((0, serialization_1.serialize)(stubMessage, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY)).rejects.toEqual(new RAMFSyntaxError_1.default('Id should not span more than 64 characters (got 65)'));
                });
            });
            describe('Date', () => {
                test('Date should be serialized with UTC and second-level precision', async () => {
                    const nonUtcDate = new Date('01 Jan 2019 12:00:00 GMT+11:00');
                    const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
                        creationDate: nonUtcDate,
                    });
                    const messageSerialized = await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                    const fields = await deserializeFields(messageSerialized);
                    const datetimeBlock = (0, _test_utils_1.getAsn1SequenceItem)(fields, 2);
                    expect(datetimeBlock.valueBlock.valueHex).toEqual((0, asn1_1.dateToASN1DateTimeInUTC)(nonUtcDate).valueBlock.valueHex);
                });
            });
            describe('TTL', () => {
                test('TTL should be serialized as an integer', async () => {
                    const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
                    const messageSerialized = await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                    const fields = await deserializeFields(messageSerialized);
                    const ttlBlock = (0, _test_utils_1.getAsn1SequenceItem)(fields, 3);
                    const ttlIntegerBlock = new asn1js.Integer({
                        valueHex: ttlBlock.valueBlock.valueHexView,
                    });
                    expect(Number(ttlIntegerBlock.toBigInt())).toEqual(message.ttl);
                });
                test('TTL of zero should be accepted', async () => {
                    const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
                        ttl: 0,
                    });
                    const messageSerialized = await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                    const fields = await deserializeFields(messageSerialized);
                    const ttlBlock = (0, _test_utils_1.getAsn1SequenceItem)(fields, 3);
                    const ttlIntegerBlock = new asn1js.Integer({
                        valueHex: ttlBlock.valueBlock.valueHex,
                    });
                    expect(ttlIntegerBlock.valueBlock.valueDec).toEqual(0);
                });
                test('TTL should not be negative', async () => {
                    const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
                        ttl: -1,
                    });
                    await expect((0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY)).rejects.toEqual(new RAMFSyntaxError_1.default('TTL cannot be negative'));
                });
                test('TTL should not be more than 180 days', async () => {
                    const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
                        ttl: MAX_TTL + 1,
                    });
                    await expect((0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY)).rejects.toEqual(new RAMFSyntaxError_1.default(`TTL must be less than ${MAX_TTL} (got ${MAX_TTL + 1})`));
                });
            });
            describe('Payload', () => {
                test('Payload should be serialized as an OCTET STRING', async () => {
                    const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
                    const messageSerialized = await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                    const fields = await deserializeFields(messageSerialized);
                    const payloadBlock = (0, _test_utils_1.getAsn1SequenceItem)(fields, 4);
                    expect(Buffer.from(payloadBlock.valueBlock.valueHex)).toEqual(PAYLOAD);
                });
                test('Payload can span up to 8 MiB', async () => {
                    const largePayload = Buffer.from('a'.repeat(MAX_PAYLOAD_LENGTH));
                    const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, largePayload);
                    const messageSerialized = await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                    const fields = await deserializeFields(messageSerialized);
                    const payloadBlock = (0, _test_utils_1.getAsn1SequenceItem)(fields, 4);
                    expect(Buffer.from(payloadBlock.valueBlock.valueHex)).toEqual(largePayload);
                });
                test('Payload size should not exceed 8 MiB', async () => {
                    const largePayload = Buffer.from('a'.repeat(MAX_PAYLOAD_LENGTH + 1));
                    const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, largePayload);
                    await expect((0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY)).rejects.toEqual(new RAMFSyntaxError_1.default(`Payload size must not exceed 8 MiB (got ${largePayload.byteLength} octets)`));
                });
            });
            async function deserializeFields(messageSerialized) {
                // Skip format signature
                const cmsSignedDataSerialized = messageSerialized.slice(10);
                const { plaintext } = await cmsSignedData.verifySignature(cmsSignedDataSerialized);
                return (0, _utils_1.derDeserialize)(plaintext);
            }
        });
    });
    describe('deserialize', () => {
        const octetsIn9Mib = 9437184;
        test('Messages up to 9 MiB should be accepted', async () => {
            const serialization = (0, buffer_to_arraybuffer_1.default)(Buffer.from('a'.repeat(octetsIn9Mib)));
            // Deserialization still fails, but for a different reason
            await expect((0, serialization_1.deserialize)(serialization, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toThrowWithMessage(RAMFSyntaxError_1.default, 'RAMF format signature does not begin with "Relaynet"');
        });
        test('Messages larger than 9 MiB should be refused', async () => {
            const serializationLength = octetsIn9Mib + 1;
            const serialization = (0, buffer_to_arraybuffer_1.default)(Buffer.from('a'.repeat(serializationLength)));
            await expect((0, serialization_1.deserialize)(serialization, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toMatchObject({
                message: `Message should not be longer than 9 MiB (got ${serializationLength} octets)`,
            });
        });
        describe('Format signature', () => {
            test('Input should be long enough to contain format signature', async () => {
                const serialization = (0, buffer_to_arraybuffer_1.default)(Buffer.from('a'.repeat(9)));
                await expect((0, serialization_1.deserialize)(serialization, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toThrowWithMessage(RAMFSyntaxError_1.default, 'Serialization is too small to contain RAMF format signature');
            });
            test('Input should be refused if it does not start with "Relaynet"', async () => {
                const serialization = (0, buffer_to_arraybuffer_1.default)(Buffer.from('Relaycorp00'));
                await expect((0, serialization_1.deserialize)(serialization, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toThrowWithMessage(RAMFSyntaxError_1.default, 'RAMF format signature does not begin with "Relaynet"');
            });
            test('A non-matching concrete message type should be refused', async () => {
                const altMessage = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
                const serialization = await (0, serialization_1.serialize)(altMessage, stubConcreteMessageTypeOctet + 1, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                await expect((0, serialization_1.deserialize)(serialization, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toThrowWithMessage(RAMFSyntaxError_1.default, 'Expected concrete message type 0x44 but got 0x45');
            });
            test('A non-matching concrete message version should be refused', async () => {
                const altMessage = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
                const serialization = await (0, serialization_1.serialize)(altMessage, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet + 1, SENDER_PRIVATE_KEY);
                await expect((0, serialization_1.deserialize)(serialization, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toThrowWithMessage(RAMFSyntaxError_1.default, 'Expected concrete message version 0x2 but got 0x3');
            });
        });
        describe('SignedData', () => {
            test('Signature should not be accepted if invalid', async () => {
                const differentSignerKeyPair = await (0, keys_1.generateRSAKeyPair)();
                const differentSignerCertificate = await (0, _test_utils_1.generateStubCert)({
                    issuerPrivateKey: differentSignerKeyPair.privateKey,
                    subjectPublicKey: differentSignerKeyPair.publicKey,
                });
                const messageSerialized = await serializeRamfWithoutValidation([], differentSignerCertificate);
                const error = await (0, _test_utils_1.getPromiseRejection)((0, serialization_1.deserialize)(messageSerialized, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage));
                expect(error).toBeInstanceOf(RAMFValidationError_1.default);
                expect(error.message).toStartWith('Invalid RAMF message signature: Invalid signature:');
            });
            test('Sender certificate should be extracted from signature', async () => {
                const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
                const messageSerialized = await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                const messageDeserialized = await (0, serialization_1.deserialize)(messageSerialized, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage);
                (0, _test_utils_1.expectPkijsValuesToBeEqual)(messageDeserialized.senderCertificate.pkijsCertificate, SENDER_CERTIFICATE.pkijsCertificate);
            });
            test('Sender certificate chain should be extracted from signature', async () => {
                const caCertificate = await (0, _test_utils_1.generateStubCert)();
                const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, {
                    senderCaCertificateChain: [caCertificate],
                });
                const messageSerialized = await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                const { senderCaCertificateChain } = await (0, serialization_1.deserialize)(messageSerialized, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage);
                expect(senderCaCertificateChain).toHaveLength(1);
                expect(senderCaCertificateChain[0].isEqual(caCertificate)).toBeTrue();
            });
        });
        describe('Fields', () => {
            test('Fields should be DER-encoded', async () => {
                const serializer = new smart_buffer_1.SmartBuffer();
                serializer.writeString('Relaynet');
                serializer.writeUInt8(stubConcreteMessageTypeOctet);
                serializer.writeUInt8(stubConcreteMessageVersionOctet);
                serializer.writeBuffer(Buffer.from(await cmsSignedData.sign((0, buffer_to_arraybuffer_1.default)(Buffer.from('Not a DER value')), SENDER_PRIVATE_KEY, SENDER_CERTIFICATE)));
                const serialization = serializer.toBuffer();
                await expect((0, serialization_1.deserialize)((0, buffer_to_arraybuffer_1.default)(serialization), stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toEqual(new RAMFSyntaxError_1.default('Invalid RAMF fields'));
            });
            test('Fields should be serialized as a sequence', async () => {
                const serializer = new smart_buffer_1.SmartBuffer();
                serializer.writeString('Relaynet');
                serializer.writeUInt8(stubConcreteMessageTypeOctet);
                serializer.writeUInt8(stubConcreteMessageVersionOctet);
                const signedData = await cmsSignedData.SignedData.sign(new asn1js.Null().toBER(false), SENDER_PRIVATE_KEY, SENDER_CERTIFICATE);
                serializer.writeBuffer(Buffer.from(signedData.serialize()));
                const serialization = serializer.toBuffer();
                await expect((0, serialization_1.deserialize)((0, buffer_to_arraybuffer_1.default)(serialization), stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toEqual(new RAMFSyntaxError_1.default('Invalid RAMF fields'));
            });
            test('Fields sequence should not have fewer than 5 items', async () => {
                const serialization = await serializeRamfWithoutValidation([
                    new asn1js.VisibleString({ value: 'address' }),
                    new asn1js.VisibleString({ value: 'the-id' }),
                    (0, asn1_1.dateToASN1DateTimeInUTC)(NOW),
                    new asn1js.Integer({ value: 1000 }),
                ]);
                await expect((0, serialization_1.deserialize)(serialization, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toEqual(new RAMFSyntaxError_1.default('Invalid RAMF fields'));
            });
            describe('Recipient address', () => {
                test('Address should be extracted', async () => {
                    const address = 'a'.repeat(1024);
                    const message = new _test_utils_2.StubMessage(address, SENDER_CERTIFICATE, PAYLOAD);
                    const serialization = await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                    const deserialization = await (0, serialization_1.deserialize)(serialization, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage);
                    expect(deserialization.recipientAddress).toEqual(address);
                });
                test('Address should not span more than 1024 octets', async () => {
                    const address = 'a'.repeat(1025);
                    const messageSerialized = await serializeRamfWithoutValidation([
                        new asn1js.VisibleString({ value: address }),
                        new asn1js.VisibleString({ value: 'the-id' }),
                        (0, asn1_1.dateToASN1DateTimeInUTC)(NOW),
                        new asn1js.Integer({ value: 1000 }),
                        new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }),
                    ]);
                    await expect((0, serialization_1.deserialize)(messageSerialized, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toEqual(new RAMFSyntaxError_1.default('Recipient address should not span more than 1024 characters (got 1025)'));
                });
                test('Private addresses should be accepted', async () => {
                    const address = '0deadbeef';
                    const message = new _test_utils_2.StubMessage(address, SENDER_CERTIFICATE, PAYLOAD);
                    const serialization = await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                    const deserialization = await (0, serialization_1.deserialize)(serialization, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage);
                    expect(deserialization.recipientAddress).toEqual(address);
                });
                test('Public addresses should be accepted', async () => {
                    const address = 'https://example.com';
                    const message = new _test_utils_2.StubMessage(address, SENDER_CERTIFICATE, PAYLOAD);
                    const serialization = await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                    const deserialization = await (0, serialization_1.deserialize)(serialization, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage);
                    expect(deserialization.recipientAddress).toEqual(address);
                });
                test('Invalid addresses should be refused', async () => {
                    const invalidAddress = 'not valid';
                    const message = new _test_utils_2.StubMessage(invalidAddress, SENDER_CERTIFICATE, PAYLOAD);
                    const serialization = await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                    await expect((0, serialization_1.deserialize)(serialization, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toEqual(new RAMFSyntaxError_1.default(`Recipient address should be a valid node address (got: "${invalidAddress}")`));
                });
            });
            describe('Message id', () => {
                test('Id should be deserialized', async () => {
                    const id = 'a'.repeat(64);
                    const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD, { id });
                    const serialization = await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                    const deserialization = await (0, serialization_1.deserialize)(serialization, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage);
                    expect(deserialization.id).toEqual(id);
                });
                test('Id should not exceed 64 characters', async () => {
                    const id = 'a'.repeat(65);
                    const messageSerialized = await serializeRamfWithoutValidation([
                        new asn1js.VisibleString({ value: RECIPIENT_ADDRESS }),
                        new asn1js.VisibleString({ value: id }),
                        (0, asn1_1.dateToASN1DateTimeInUTC)(NOW),
                        new asn1js.Integer({ value: 1000 }),
                        new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }),
                    ]);
                    await expect((0, serialization_1.deserialize)(messageSerialized, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toEqual(new RAMFSyntaxError_1.default('Id should not span more than 64 characters (got 65)'));
                });
            });
            describe('Date', () => {
                test('Valid date should be accepted', async () => {
                    const date = moment_1.default.utc(NOW).format('YYYYMMDDHHmmss');
                    const messageSerialized = await serializeRamfWithoutValidation([
                        new asn1js.VisibleString({ value: RECIPIENT_ADDRESS }),
                        new asn1js.VisibleString({ value: 'id' }),
                        new asn1js.DateTime({ value: date }),
                        new asn1js.Integer({ value: 1000 }),
                        new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }),
                    ]);
                    const message = await (0, serialization_1.deserialize)(messageSerialized, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage);
                    expect(message.creationDate).toEqual(NOW);
                });
                test('Date not serialized as an ASN.1 DATE-TIME should be refused', async () => {
                    const messageSerialized = await serializeRamfWithoutValidation([
                        new asn1js.VisibleString({ value: 'the-address' }),
                        new asn1js.VisibleString({ value: 'id' }),
                        new asn1js.DateTime({ value: '42' }),
                        new asn1js.Integer({ value: 1000 }),
                        new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }),
                    ]);
                    await expect((0, serialization_1.deserialize)(messageSerialized, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toMatchObject({
                        message: /^Message date is invalid:/,
                    });
                });
            });
            describe('TTL', () => {
                test('TTL of exactly 180 days should be accepted', async () => {
                    const messageSerialized = await serializeRamfWithoutValidation([
                        new asn1js.VisibleString({ value: RECIPIENT_ADDRESS }),
                        new asn1js.VisibleString({ value: 'the-id' }),
                        (0, asn1_1.dateToASN1DateTimeInUTC)(NOW),
                        new asn1js.Integer({ value: MAX_TTL }),
                        new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }),
                    ]);
                    await expect((0, serialization_1.deserialize)(messageSerialized, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).resolves.toHaveProperty('ttl', MAX_TTL);
                });
                test('TTL greater than 180 days should not be accepted', async () => {
                    const messageSerialized = await serializeRamfWithoutValidation([
                        new asn1js.VisibleString({ value: RECIPIENT_ADDRESS }),
                        new asn1js.VisibleString({ value: 'the-id' }),
                        (0, asn1_1.dateToASN1DateTimeInUTC)(NOW),
                        new asn1js.Integer({ value: MAX_TTL + 1 }),
                        new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }),
                    ]);
                    await expect((0, serialization_1.deserialize)(messageSerialized, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toEqual(new RAMFSyntaxError_1.default(`TTL must be less than ${MAX_TTL} (got ${MAX_TTL + 1})`));
                });
            });
            describe('Payload', () => {
                test('Payload should be extracted', async () => {
                    const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
                    const messageSerialized = await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
                    const messageDeserialized = await (0, serialization_1.deserialize)(messageSerialized, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage);
                    expect(messageDeserialized.payloadSerialized).toEqual(PAYLOAD);
                });
                test('Payload size should not exceed 8 MiB', async () => {
                    const largePayload = Buffer.from('a'.repeat(MAX_PAYLOAD_LENGTH + 1));
                    const messageSerialized = await serializeRamfWithoutValidation([
                        new asn1js.VisibleString({ value: RECIPIENT_ADDRESS }),
                        new asn1js.VisibleString({ value: 'the-id' }),
                        (0, asn1_1.dateToASN1DateTimeInUTC)(NOW),
                        new asn1js.Integer({ value: 1000 }),
                        new asn1js.OctetString({ valueHex: (0, buffer_to_arraybuffer_1.default)(largePayload) }),
                    ]);
                    await expect((0, serialization_1.deserialize)(messageSerialized, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage)).rejects.toMatchObject({
                        message: `Payload size must not exceed 8 MiB (got ${largePayload.byteLength} octets)`,
                    });
                });
            });
        });
        test('Valid messages should be successfully deserialized', async () => {
            const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, SENDER_CERTIFICATE, PAYLOAD);
            const messageSerialized = await (0, serialization_1.serialize)(message, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, SENDER_PRIVATE_KEY);
            jest.spyOn(cmsSignedData, 'verifySignature');
            const messageDeserialized = await (0, serialization_1.deserialize)(messageSerialized, stubConcreteMessageTypeOctet, stubConcreteMessageVersionOctet, _test_utils_2.StubMessage);
            expect(messageDeserialized.recipientAddress).toEqual(message.recipientAddress);
            expect(messageDeserialized.senderCertificate.isEqual(message.senderCertificate)).toBeTrue();
            expect(messageDeserialized.payloadSerialized).toEqual(message.payloadSerialized);
        });
        async function serializeRamfWithoutValidation(sequenceItems, senderCertificate) {
            const serializer = new smart_buffer_1.SmartBuffer();
            serializer.writeString('Relaynet');
            serializer.writeUInt8(stubConcreteMessageTypeOctet);
            serializer.writeUInt8(stubConcreteMessageVersionOctet);
            const signedData = await cmsSignedData.SignedData.sign((0, asn1_1.makeImplicitlyTaggedSequence)(...sequenceItems).toBER(), SENDER_PRIVATE_KEY, senderCertificate ?? SENDER_CERTIFICATE);
            serializer.writeBuffer(Buffer.from(signedData.serialize()));
            return (0, buffer_to_arraybuffer_1.default)(serializer.toBuffer());
        }
    });
});
function parseFormatSignature(messageSerialized) {
    const buffer = Buffer.from(messageSerialized);
    return {
        concreteMessageType: buffer.readUInt8(8),
        concreteMessageVersion: buffer.readUInt8(9),
        magic: buffer.slice(0, 8).toString(),
    };
}
//# sourceMappingURL=serialization.spec.js.map