"use strict";
// tslint:disable:max-classes-per-file
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
const jestDateMock = __importStar(require("jest-date-mock"));
const _test_utils_1 = require("../_test_utils");
const envelopedData_1 = require("../crypto_wrappers/cms/envelopedData");
const keys_1 = require("../crypto_wrappers/keys");
const CertificateError_1 = __importDefault(require("../crypto_wrappers/x509/CertificateError"));
const testMocks_1 = require("../keyStores/testMocks");
const _test_utils_2 = require("../ramf/_test_utils");
const RAMFError_1 = __importDefault(require("../ramf/RAMFError"));
const SessionKeyPair_1 = require("../SessionKeyPair");
const InvalidMessageError_1 = __importDefault(require("./InvalidMessageError"));
const RecipientAddressType_1 = require("./RecipientAddressType");
const mockStubUuid4 = '56e95d8a-6be2-4020-bb36-5dd0da36c181';
jest.mock('uuid4', () => {
    return {
        __esModule: true,
        default: jest.fn().mockImplementation(() => mockStubUuid4),
    };
});
const STUB_PAYLOAD_PLAINTEXT = Buffer.from('Hi');
afterEach(() => {
    jest.restoreAllMocks();
    jestDateMock.clear();
});
describe('RAMFMessage', () => {
    let recipientPrivateAddress;
    let recipientCertificate;
    let senderCertificate;
    beforeAll(async () => {
        const recipientKeyPair = await (0, keys_1.generateRSAKeyPair)();
        recipientCertificate = await (0, _test_utils_1.generateStubCert)({
            attributes: { isCA: true },
            subjectPublicKey: recipientKeyPair.publicKey,
        });
        recipientPrivateAddress = recipientCertificate.getCommonName();
        const senderKeyPair = await (0, keys_1.generateRSAKeyPair)();
        senderCertificate = (0, _test_utils_1.reSerializeCertificate)(await (0, _test_utils_1.generateStubCert)({
            subjectPublicKey: senderKeyPair.publicKey,
        }));
    });
    let stubSenderChain;
    beforeAll(async () => {
        stubSenderChain = await generateAuthorizedSenderChain();
    });
    describe('constructor', () => {
        describe('Id', () => {
            test('Id should fall back to UUID4 when left unspecified', () => {
                const message = new _test_utils_2.StubMessage(recipientPrivateAddress, senderCertificate, STUB_PAYLOAD_PLAINTEXT);
                expect(message.id).toEqual(mockStubUuid4);
            });
        });
        describe('Date', () => {
            test('The current date (UTC) should be used by default', () => {
                const now = new Date(2019, 1, 1, 1, 1, 1, 1);
                jestDateMock.advanceTo(now);
                const message = new _test_utils_2.StubMessage(recipientPrivateAddress, senderCertificate, STUB_PAYLOAD_PLAINTEXT);
                const expectedDate = new Date(now.getTime());
                expectedDate.setMilliseconds(0);
                expect(message.creationDate).toEqual(expectedDate);
            });
            test('A custom date should be accepted', () => {
                const date = new Date(2020, 1, 1, 1, 1, 1, 1);
                const message = new _test_utils_2.StubMessage(recipientPrivateAddress, senderCertificate, STUB_PAYLOAD_PLAINTEXT, { creationDate: date });
                const expectedDate = new Date(date.getTime());
                expectedDate.setMilliseconds(0);
                expect(message.creationDate).toEqual(expectedDate);
            });
        });
        describe('TTL', () => {
            test('TTL should be 5 minutes by default', () => {
                const message = new _test_utils_2.StubMessage(recipientPrivateAddress, senderCertificate, STUB_PAYLOAD_PLAINTEXT);
                expect(message.ttl).toEqual(5 * 60);
            });
            test('A custom TTL under 2^24 should be accepted', () => {
                const ttl = 2 ** 24 - 1;
                const message = new _test_utils_2.StubMessage(recipientPrivateAddress, senderCertificate, STUB_PAYLOAD_PLAINTEXT, { ttl });
                expect(message.ttl).toEqual(ttl);
            });
        });
        describe('Sender CA certificate chain', () => {
            test('CA certificate chain should be empty by default', () => {
                const message = new _test_utils_2.StubMessage(recipientPrivateAddress, senderCertificate, STUB_PAYLOAD_PLAINTEXT);
                expect(message.senderCaCertificateChain).toEqual([]);
            });
            test('A custom sender certificate chain should be accepted', async () => {
                const chain = [await (0, _test_utils_1.generateStubCert)(), await (0, _test_utils_1.generateStubCert)()];
                const message = new _test_utils_2.StubMessage(recipientPrivateAddress, senderCertificate, STUB_PAYLOAD_PLAINTEXT, { senderCaCertificateChain: chain });
                expect(message.senderCaCertificateChain).toEqual(chain);
            });
            test('Sender certificate should be excluded from chain if included', async () => {
                const chain = [await (0, _test_utils_1.generateStubCert)()];
                const message = new _test_utils_2.StubMessage(recipientPrivateAddress, senderCertificate, STUB_PAYLOAD_PLAINTEXT, {
                    senderCaCertificateChain: [...chain, senderCertificate],
                });
                expect(message.senderCaCertificateChain).toEqual(chain);
            });
        });
    });
    test('getSenderCertificationPath should return certification path', async () => {
        const message = new _test_utils_2.StubMessage(await stubSenderChain.recipientCert.calculateSubjectPrivateAddress(), stubSenderChain.senderCert, STUB_PAYLOAD_PLAINTEXT, {
            senderCaCertificateChain: [stubSenderChain.recipientCert],
        });
        await expect(message.getSenderCertificationPath([stubSenderChain.rootCert])).resolves.toEqual([
            expect.toSatisfy((c) => c.isEqual(stubSenderChain.senderCert)),
            expect.toSatisfy((c) => c.isEqual(stubSenderChain.recipientCert)),
            expect.toSatisfy((c) => c.isEqual(stubSenderChain.rootCert)),
        ]);
    });
    test('expiryDate field should calculate expiry date from creation date and TTL', () => {
        const message = new _test_utils_2.StubMessage('some-address', stubSenderChain.senderCert, STUB_PAYLOAD_PLAINTEXT, {
            creationDate: new Date('2020-04-07T21:00:00Z'),
            ttl: 5,
        });
        const expectedExpiryDate = new Date(message.creationDate.getTime());
        expectedExpiryDate.setSeconds(expectedExpiryDate.getSeconds() + message.ttl);
        expect(message.expiryDate).toEqual(expectedExpiryDate);
    });
    describe('validate', () => {
        describe('Recipient address', () => {
            const PRIVATE_ADDRESS = '0deadbeef';
            const PUBLIC_ADDRESS = 'https://example.com';
            test('Public address should be allowed if no specific type is required', async () => {
                const message = new _test_utils_2.StubMessage(PUBLIC_ADDRESS, senderCertificate, STUB_PAYLOAD_PLAINTEXT);
                await message.validate();
            });
            test('Private address should be allowed if no specific type is required', async () => {
                const message = new _test_utils_2.StubMessage(PRIVATE_ADDRESS, senderCertificate, STUB_PAYLOAD_PLAINTEXT);
                await message.validate();
            });
            test('Syntactically-invalid addresses should be refused', async () => {
                const message = new _test_utils_2.StubMessage('this is an invalid address', senderCertificate, STUB_PAYLOAD_PLAINTEXT);
                const error = await (0, _test_utils_1.getPromiseRejection)(message.validate());
                expect(error).toBeInstanceOf(InvalidMessageError_1.default);
                expect(error.message).toEqual('Recipient address is malformed');
            });
            test('Private address should be refused if a public one is required', async () => {
                const message = new _test_utils_2.StubMessage(PRIVATE_ADDRESS, senderCertificate, STUB_PAYLOAD_PLAINTEXT);
                const error = await (0, _test_utils_1.getPromiseRejection)(message.validate(RecipientAddressType_1.RecipientAddressType.PUBLIC));
                expect(error).toBeInstanceOf(InvalidMessageError_1.default);
                expect(error.message).toEqual('Recipient address should be public but got a private one');
            });
            test('Public address should be refused if a private one is required', async () => {
                const message = new _test_utils_2.StubMessage(PUBLIC_ADDRESS, senderCertificate, STUB_PAYLOAD_PLAINTEXT);
                const error = await (0, _test_utils_1.getPromiseRejection)(message.validate(RecipientAddressType_1.RecipientAddressType.PRIVATE));
                expect(error).toBeInstanceOf(InvalidMessageError_1.default);
                expect(error.message).toEqual('Recipient address should be private but got a public one');
            });
            test('Private address should be allowed if a private one is required', async () => {
                const message = new _test_utils_2.StubMessage(PRIVATE_ADDRESS, senderCertificate, STUB_PAYLOAD_PLAINTEXT);
                await message.validate(RecipientAddressType_1.RecipientAddressType.PRIVATE);
            });
            test('Public address should be allowed if a public one is required', async () => {
                const message = new _test_utils_2.StubMessage(PUBLIC_ADDRESS, senderCertificate, STUB_PAYLOAD_PLAINTEXT);
                await message.validate(RecipientAddressType_1.RecipientAddressType.PUBLIC);
            });
        });
        describe('Authorization without trusted certificates', () => {
            test('Invalid sender certificate should be refused', async () => {
                const validityStartDate = new Date();
                validityStartDate.setMinutes(validityStartDate.getMinutes() + 1);
                const invalidSenderCertificate = await (0, _test_utils_1.generateStubCert)({
                    attributes: { validityStartDate },
                });
                const message = new _test_utils_2.StubMessage('0deadbeef', invalidSenderCertificate, STUB_PAYLOAD_PLAINTEXT);
                await expect(message.validate()).rejects.toBeInstanceOf(CertificateError_1.default);
            });
            test('Valid sender certificate should be allowed', async () => {
                const message = new _test_utils_2.StubMessage('0deadbeef', senderCertificate, STUB_PAYLOAD_PLAINTEXT);
                await expect(message.validate()).resolves.toBeNull();
            });
        });
        describe('Authorization with trusted certificates', () => {
            test('Message should be refused if sender is not trusted', async () => {
                const message = new _test_utils_2.StubMessage(await stubSenderChain.recipientCert.calculateSubjectPrivateAddress(), senderCertificate, STUB_PAYLOAD_PLAINTEXT);
                jestDateMock.advanceBy(1000);
                await expect(message.validate(undefined, [stubSenderChain.rootCert])).rejects.toEqual(new InvalidMessageError_1.default('Sender is not authorized: No valid certificate paths found'));
            });
            test('Message should be accepted if sender is trusted', async () => {
                const message = new _test_utils_2.StubMessage(await stubSenderChain.recipientCert.calculateSubjectPrivateAddress(), stubSenderChain.senderCert, STUB_PAYLOAD_PLAINTEXT, {
                    senderCaCertificateChain: [stubSenderChain.recipientCert],
                });
                jestDateMock.advanceBy(1000);
                const certificationPath = await message.validate(undefined, [stubSenderChain.rootCert]);
                expect(certificationPath).toHaveLength(3);
                expect(certificationPath[0].isEqual(message.senderCertificate)).toBeTrue();
                expect(certificationPath[1].isEqual(stubSenderChain.recipientCert)).toBeTrue();
                expect(certificationPath[2].isEqual(stubSenderChain.rootCert)).toBeTrue();
            });
            test('Message should be refused if recipient is private and did not authorize', async () => {
                const message = new _test_utils_2.StubMessage('0deadbeef', stubSenderChain.senderCert, STUB_PAYLOAD_PLAINTEXT, {
                    senderCaCertificateChain: [stubSenderChain.recipientCert],
                });
                jestDateMock.advanceBy(1000);
                await expect(message.validate(undefined, [stubSenderChain.rootCert])).rejects.toEqual(new InvalidMessageError_1.default(`Sender is not authorized to reach ${message.recipientAddress}`));
            });
            test('Message should be accepted if recipient address is public', async () => {
                const message = new _test_utils_2.StubMessage('https://example.com', stubSenderChain.senderCert, STUB_PAYLOAD_PLAINTEXT, {
                    senderCaCertificateChain: [stubSenderChain.recipientCert],
                });
                jestDateMock.advanceBy(1000);
                const certificationPath = await message.validate(undefined, [stubSenderChain.rootCert]);
                expect(certificationPath).toHaveLength(3);
                expect(certificationPath[2].isEqual(stubSenderChain.rootCert)).toBeTrue();
                expect(certificationPath[1].isEqual(stubSenderChain.recipientCert)).toBeTrue();
                expect(certificationPath[0].isEqual(message.senderCertificate)).toBeTrue();
            });
        });
        describe('Validity period', () => {
            const recipientPublicAddress = 'https://example.com';
            test('Date equal to the current date should be accepted', async () => {
                const stubDate = new Date(senderCertificate.pkijsCertificate.notAfter.value.getTime() - 1000);
                stubDate.setSeconds(0, 0);
                const message = new _test_utils_2.StubMessage(recipientPublicAddress, senderCertificate, STUB_PAYLOAD_PLAINTEXT, { creationDate: stubDate });
                jestDateMock.advanceTo(stubDate);
                await message.validate();
            });
            test('Date should not be in the future', async () => {
                const message = new _test_utils_2.StubMessage(recipientPublicAddress, senderCertificate, STUB_PAYLOAD_PLAINTEXT);
                message.creationDate.setMilliseconds(0);
                const oneSecondAgo = new Date(message.creationDate);
                oneSecondAgo.setDate(oneSecondAgo.getDate() - 1000);
                jestDateMock.advanceTo(oneSecondAgo);
                await expect(message.validate()).rejects.toEqual(new InvalidMessageError_1.default('Message date is in the future'));
            });
            test('TTL matching current time should be accepted', async () => {
                const message = new _test_utils_2.StubMessage(recipientPublicAddress, senderCertificate, STUB_PAYLOAD_PLAINTEXT, {
                    creationDate: senderCertificate.startDate,
                    ttl: 1,
                });
                jestDateMock.advanceTo(message.expiryDate);
                await message.validate();
            });
            test('TTL in the past should not be accepted', async () => {
                const message = new _test_utils_2.StubMessage(recipientPublicAddress, senderCertificate, STUB_PAYLOAD_PLAINTEXT, { ttl: 1 });
                jestDateMock.advanceTo(message.creationDate.getTime() + (message.ttl + 1) * 1000);
                await expect(message.validate()).rejects.toEqual(new InvalidMessageError_1.default('Message already expired'));
            });
        });
    });
    describe('unwrapPayload', () => {
        test('SessionlessEnvelopedData payload should be unsupported', async () => {
            const envelopedData = await envelopedData_1.SessionlessEnvelopedData.encrypt(STUB_PAYLOAD_PLAINTEXT, recipientCertificate);
            const recipientKeyStore = new testMocks_1.MockPrivateKeyStore();
            const stubMessage = new _test_utils_2.StubMessage(recipientPrivateAddress, senderCertificate, Buffer.from(envelopedData.serialize()));
            await expect(stubMessage.unwrapPayload(recipientKeyStore)).rejects.toThrowWithMessage(RAMFError_1.default, 'Sessionless payloads are no longer supported');
        });
        test('Payload for private recipient should be decrypted with key store', async () => {
            const recipientSessionKeyPair = await SessionKeyPair_1.SessionKeyPair.generate();
            const { envelopedData } = await envelopedData_1.SessionEnvelopedData.encrypt(STUB_PAYLOAD_PLAINTEXT, recipientSessionKeyPair.sessionKey);
            const stubMessage = new _test_utils_2.StubMessage(recipientPrivateAddress, senderCertificate, Buffer.from(envelopedData.serialize()));
            const recipientKeyStore = new testMocks_1.MockPrivateKeyStore();
            await recipientKeyStore.saveSessionKey(recipientSessionKeyPair.privateKey, recipientSessionKeyPair.sessionKey.keyId, stubMessage.recipientAddress);
            const { payload, senderSessionKey } = await stubMessage.unwrapPayload(recipientKeyStore);
            expect(payload).toBeInstanceOf(_test_utils_2.StubPayload);
            expect(Buffer.from(payload.content)).toEqual(STUB_PAYLOAD_PLAINTEXT);
            expect(senderSessionKey).toEqual(await envelopedData.getOriginatorKey());
        });
        test('Payload for public recipient should be decrypted with key store', async () => {
            const recipientSessionKeyPair = await SessionKeyPair_1.SessionKeyPair.generate();
            const { envelopedData } = await envelopedData_1.SessionEnvelopedData.encrypt(STUB_PAYLOAD_PLAINTEXT, recipientSessionKeyPair.sessionKey);
            const stubMessage = new _test_utils_2.StubMessage('https://example.com', senderCertificate, Buffer.from(envelopedData.serialize()));
            const recipientKeyStore = new testMocks_1.MockPrivateKeyStore();
            await recipientKeyStore.saveSessionKey(recipientSessionKeyPair.privateKey, recipientSessionKeyPair.sessionKey.keyId, recipientPrivateAddress);
            const { payload, senderSessionKey } = await stubMessage.unwrapPayload(recipientKeyStore, recipientPrivateAddress);
            expect(payload).toBeInstanceOf(_test_utils_2.StubPayload);
            expect(Buffer.from(payload.content)).toEqual(STUB_PAYLOAD_PLAINTEXT);
            expect(senderSessionKey).toEqual(await envelopedData.getOriginatorKey());
        });
        test('Recipient private address should be passed if only public is available', async () => {
            const stubMessage = new _test_utils_2.StubMessage('https://example.com', senderCertificate, Buffer.from([]));
            const recipientKeyStore = new testMocks_1.MockPrivateKeyStore();
            await expect(stubMessage.unwrapPayload(recipientKeyStore)).rejects.toThrowWithMessage(RAMFError_1.default, 'Recipient private address should be passed because message uses public address');
        });
        test('Payload for private recipient should be decrypted with private key', async () => {
            const recipientSessionKeyPair = await SessionKeyPair_1.SessionKeyPair.generate();
            const { envelopedData } = await envelopedData_1.SessionEnvelopedData.encrypt(STUB_PAYLOAD_PLAINTEXT, recipientSessionKeyPair.sessionKey);
            const stubMessage = new _test_utils_2.StubMessage('0123', senderCertificate, Buffer.from(envelopedData.serialize()));
            const { payload } = await stubMessage.unwrapPayload(recipientSessionKeyPair.privateKey);
            expect(payload).toBeInstanceOf(_test_utils_2.StubPayload);
            expect(Buffer.from(payload.content)).toEqual(STUB_PAYLOAD_PLAINTEXT);
        });
        test('Payload for public recipient should be decrypted with private key', async () => {
            const recipientSessionKeyPair = await SessionKeyPair_1.SessionKeyPair.generate();
            const { envelopedData } = await envelopedData_1.SessionEnvelopedData.encrypt(STUB_PAYLOAD_PLAINTEXT, recipientSessionKeyPair.sessionKey);
            const stubMessage = new _test_utils_2.StubMessage('https://example.com', senderCertificate, Buffer.from(envelopedData.serialize()));
            const { payload } = await stubMessage.unwrapPayload(recipientSessionKeyPair.privateKey);
            expect(payload).toBeInstanceOf(_test_utils_2.StubPayload);
            expect(Buffer.from(payload.content)).toEqual(STUB_PAYLOAD_PLAINTEXT);
        });
    });
    describe('isRecipientAddressPrivate', () => {
        test('True should be returned when address is private', () => {
            const message = new _test_utils_2.StubMessage(recipientPrivateAddress, senderCertificate, STUB_PAYLOAD_PLAINTEXT);
            expect(message.isRecipientAddressPrivate).toBeTrue();
        });
        test('False should be returned when address is public', () => {
            const message = new _test_utils_2.StubMessage('https://example.com', senderCertificate, STUB_PAYLOAD_PLAINTEXT);
            expect(message.isRecipientAddressPrivate).toBeFalse();
        });
    });
});
async function generateAuthorizedSenderChain() {
    const rootKeyPair = await (0, keys_1.generateRSAKeyPair)();
    const rootCert = (0, _test_utils_1.reSerializeCertificate)(await (0, _test_utils_1.generateStubCert)({
        attributes: { isCA: true },
        issuerPrivateKey: rootKeyPair.privateKey,
        subjectPublicKey: rootKeyPair.publicKey,
    }));
    const recipientKeyPair = await (0, keys_1.generateRSAKeyPair)();
    const recipientCert = (0, _test_utils_1.reSerializeCertificate)(await (0, _test_utils_1.generateStubCert)({
        attributes: { isCA: true },
        issuerCertificate: rootCert,
        issuerPrivateKey: rootKeyPair.privateKey,
        subjectPublicKey: recipientKeyPair.publicKey,
    }));
    const senderCert = (0, _test_utils_1.reSerializeCertificate)(await (0, _test_utils_1.generateStubCert)({
        attributes: { isCA: false },
        issuerCertificate: recipientCert,
        issuerPrivateKey: recipientKeyPair.privateKey,
    }));
    return { recipientCert, rootCert, senderCert };
}
//# sourceMappingURL=RAMFMessage.spec.js.map