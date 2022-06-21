"use strict";
/* tslint:disable:no-let */
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.describeMessage = void 0;
const _test_utils_1 = require("../_test_utils");
const keys_1 = require("../crypto_wrappers/keys");
const serialization = __importStar(require("../ramf/serialization"));
function describeMessage(messageClass, messageType, messageVersion) {
    afterAll(() => {
        jest.restoreAllMocks();
    });
    let message;
    let senderPrivateKey;
    beforeAll(async () => {
        const senderKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const senderCertificate = await (0, _test_utils_1.generateStubCert)({
            issuerPrivateKey: senderKeyPair.privateKey,
        });
        senderPrivateKey = senderKeyPair.privateKey;
        message = new messageClass('address', senderCertificate, Buffer.from('hi'));
    });
    describe('serialize', () => {
        const expectedSerialization = (0, _test_utils_1.arrayBufferFrom)('serialized');
        const serializeSpy = jest.spyOn(serialization, 'serialize');
        beforeAll(() => {
            serializeSpy.mockResolvedValueOnce(expectedSerialization);
        });
        afterEach(() => {
            serializeSpy.mockReset();
        });
        test('Result should be RAMF serialization', async () => {
            const messageSerialized = await message.serialize(senderPrivateKey);
            expect(serializeSpy).toBeCalledTimes(1);
            expect(messageSerialized).toBe(expectedSerialization);
        });
        test(`Concrete message type should be ${messageType}`, async () => {
            await message.serialize(senderPrivateKey);
            const serializeCallArs = (0, _test_utils_1.getMockContext)(serialization.serialize).calls[0];
            expect(serializeCallArs[1]).toEqual(messageType);
        });
        test(`Concrete message version should be ${messageVersion}`, async () => {
            await message.serialize(senderPrivateKey);
            const serializeCallArs = (0, _test_utils_1.getMockContext)(serialization.serialize).calls[0];
            expect(serializeCallArs[2]).toEqual(messageVersion);
        });
        test('Message should be signed with private key specified', async () => {
            await message.serialize(senderPrivateKey);
            const serializeCallArs = (0, _test_utils_1.getMockContext)(serialization.serialize).calls[0];
            expect(serializeCallArs[3]).toEqual(senderPrivateKey);
        });
        test('Signature options should be honored', async () => {
            const signatureOptions = { hashingAlgorithmName: 'SHA-384' };
            await message.serialize(senderPrivateKey, signatureOptions);
            const serializeCallArs = (0, _test_utils_1.getMockContext)(serialization.serialize).calls[0];
            expect(serializeCallArs[4]).toEqual(signatureOptions);
        });
    });
    describe('deserialize', () => {
        const stubMessageSerialized = (0, _test_utils_1.arrayBufferFrom)('I am a message. I swear.');
        const deserializeSpy = (0, _test_utils_1.mockSpy)(jest.spyOn(serialization, 'deserialize'), async () => message);
        test('Result should be the expected message', async () => {
            const messageDeserialized = await messageClass.deserialize(stubMessageSerialized);
            expect(messageDeserialized).toBe(message);
            expect(deserializeSpy).toBeCalledTimes(1);
            const deserializeCallArgs = (0, _test_utils_1.getMockContext)(deserializeSpy).calls[0];
            expect(deserializeCallArgs[0]).toBe(stubMessageSerialized);
        });
        test(`Concrete message type should be ${messageType}`, async () => {
            await messageClass.deserialize(stubMessageSerialized);
            const deserializeCallArgs = (0, _test_utils_1.getMockContext)(deserializeSpy).calls[0];
            expect(deserializeCallArgs[1]).toEqual(messageType);
        });
        test(`Concrete message version should be ${messageVersion}`, async () => {
            await messageClass.deserialize(stubMessageSerialized);
            const deserializeCallArgs = (0, _test_utils_1.getMockContext)(deserializeSpy).calls[0];
            expect(deserializeCallArgs[2]).toEqual(messageVersion);
        });
        test(`Message class should be ${messageClass.name}`, async () => {
            await messageClass.deserialize(stubMessageSerialized);
            const deserializeCallArgs = (0, _test_utils_1.getMockContext)(deserializeSpy).calls[0];
            expect(deserializeCallArgs[3]).toBe(messageClass);
        });
    });
}
exports.describeMessage = describeMessage;
//# sourceMappingURL=_test_utils.js.map