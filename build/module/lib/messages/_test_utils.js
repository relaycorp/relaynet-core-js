/* tslint:disable:no-let */
import { arrayBufferFrom, generateStubCert, getMockContext, mockSpy } from '../_test_utils';
import { generateRSAKeyPair } from '../crypto_wrappers/keys';
import * as serialization from '../ramf/serialization';
export function describeMessage(messageClass, messageType, messageVersion) {
    afterAll(() => {
        jest.restoreAllMocks();
    });
    let message;
    let senderPrivateKey;
    beforeAll(async () => {
        const senderKeyPair = await generateRSAKeyPair();
        const senderCertificate = await generateStubCert({
            issuerPrivateKey: senderKeyPair.privateKey,
        });
        senderPrivateKey = senderKeyPair.privateKey;
        message = new messageClass('address', senderCertificate, Buffer.from('hi'));
    });
    describe('serialize', () => {
        const expectedSerialization = arrayBufferFrom('serialized');
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
            const serializeCallArs = getMockContext(serialization.serialize).calls[0];
            expect(serializeCallArs[1]).toEqual(messageType);
        });
        test(`Concrete message version should be ${messageVersion}`, async () => {
            await message.serialize(senderPrivateKey);
            const serializeCallArs = getMockContext(serialization.serialize).calls[0];
            expect(serializeCallArs[2]).toEqual(messageVersion);
        });
        test('Message should be signed with private key specified', async () => {
            await message.serialize(senderPrivateKey);
            const serializeCallArs = getMockContext(serialization.serialize).calls[0];
            expect(serializeCallArs[3]).toEqual(senderPrivateKey);
        });
        test('Signature options should be honored', async () => {
            const signatureOptions = { hashingAlgorithmName: 'SHA-384' };
            await message.serialize(senderPrivateKey, signatureOptions);
            const serializeCallArs = getMockContext(serialization.serialize).calls[0];
            expect(serializeCallArs[4]).toEqual(signatureOptions);
        });
    });
    describe('deserialize', () => {
        const stubMessageSerialized = arrayBufferFrom('I am a message. I swear.');
        const deserializeSpy = mockSpy(jest.spyOn(serialization, 'deserialize'), async () => message);
        test('Result should be the expected message', async () => {
            const messageDeserialized = await messageClass.deserialize(stubMessageSerialized);
            expect(messageDeserialized).toBe(message);
            expect(deserializeSpy).toBeCalledTimes(1);
            const deserializeCallArgs = getMockContext(deserializeSpy).calls[0];
            expect(deserializeCallArgs[0]).toBe(stubMessageSerialized);
        });
        test(`Concrete message type should be ${messageType}`, async () => {
            await messageClass.deserialize(stubMessageSerialized);
            const deserializeCallArgs = getMockContext(deserializeSpy).calls[0];
            expect(deserializeCallArgs[1]).toEqual(messageType);
        });
        test(`Concrete message version should be ${messageVersion}`, async () => {
            await messageClass.deserialize(stubMessageSerialized);
            const deserializeCallArgs = getMockContext(deserializeSpy).calls[0];
            expect(deserializeCallArgs[2]).toEqual(messageVersion);
        });
        test(`Message class should be ${messageClass.name}`, async () => {
            await messageClass.deserialize(stubMessageSerialized);
            const deserializeCallArgs = getMockContext(deserializeSpy).calls[0];
            expect(deserializeCallArgs[3]).toBe(messageClass);
        });
    });
}
//# sourceMappingURL=_test_utils.js.map