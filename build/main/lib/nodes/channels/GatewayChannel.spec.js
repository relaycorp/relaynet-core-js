"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const date_fns_1 = require("date-fns");
const _test_utils_1 = require("../../_test_utils");
const envelopedData_1 = require("../../crypto_wrappers/cms/envelopedData");
const keys_1 = require("../../crypto_wrappers/keys");
const testMocks_1 = require("../../keyStores/testMocks");
const Cargo_1 = __importDefault(require("../../messages/Cargo"));
const Parcel_1 = __importDefault(require("../../messages/Parcel"));
const ServiceMessage_1 = __importDefault(require("../../messages/payloads/ServiceMessage"));
const issuance_1 = require("../../pki/issuance");
const serialization_1 = require("../../ramf/serialization");
const SessionKeyPair_1 = require("../../SessionKeyPair");
const GatewayChannel_1 = require("./GatewayChannel");
const MESSAGE = Buffer.from('This is a message to be included in a cargo');
const TOMORROW = (0, date_fns_1.setMilliseconds)((0, date_fns_1.addDays)(new Date(), 1), 0);
let peerPrivateAddress;
let peerPublicKey;
let nodePrivateKey;
let nodeCertificate;
beforeAll(async () => {
    const tomorrow = (0, date_fns_1.setMilliseconds)((0, date_fns_1.addDays)(new Date(), 1), 0);
    const peerKeyPair = await (0, keys_1.generateRSAKeyPair)();
    peerPrivateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(peerKeyPair.publicKey);
    peerPublicKey = peerKeyPair.publicKey;
    const peerCertificate = (0, _test_utils_1.reSerializeCertificate)(await (0, issuance_1.issueGatewayCertificate)({
        issuerPrivateKey: peerKeyPair.privateKey,
        subjectPublicKey: peerKeyPair.publicKey,
        validityEndDate: tomorrow,
    }));
    const nodeKeyPair = await (0, keys_1.generateRSAKeyPair)();
    nodePrivateKey = nodeKeyPair.privateKey;
    nodeCertificate = (0, _test_utils_1.reSerializeCertificate)(await (0, issuance_1.issueGatewayCertificate)({
        issuerCertificate: peerCertificate,
        issuerPrivateKey: peerKeyPair.privateKey,
        subjectPublicKey: nodeKeyPair.publicKey,
        validityEndDate: tomorrow,
    }));
});
const KEY_STORES = new testMocks_1.MockKeyStoreSet();
afterEach(() => {
    KEY_STORES.clear();
});
describe('generateCargoes', () => {
    let peerSessionKeyPair;
    beforeAll(async () => {
        peerSessionKeyPair = await SessionKeyPair_1.SessionKeyPair.generate();
    });
    beforeEach(async () => {
        await KEY_STORES.publicKeyStore.saveSessionKey(peerSessionKeyPair.sessionKey, peerPrivateAddress, new Date());
    });
    test('Recipient address should correspond to that of peer', async () => {
        const channel = new StubGatewayChannel();
        const cargoesSerialized = await (0, _test_utils_1.asyncIterableToArray)(channel.generateCargoes((0, _test_utils_1.arrayToAsyncIterable)([
            {
                expiryDate: TOMORROW,
                message: MESSAGE,
            },
        ])));
        const cargo = await Cargo_1.default.deserialize((0, buffer_to_arraybuffer_1.default)(cargoesSerialized[0]));
        expect(cargo.recipientAddress).toEqual(StubGatewayChannel.OUTBOUND_RAMF_ADDRESS);
    });
    test('Payload should be encrypted with session key', async () => {
        const channel = new StubGatewayChannel();
        const cargoesSerialized = await (0, _test_utils_1.asyncIterableToArray)(channel.generateCargoes((0, _test_utils_1.arrayToAsyncIterable)([
            {
                expiryDate: TOMORROW,
                message: MESSAGE,
            },
        ])));
        const cargo = await Cargo_1.default.deserialize((0, buffer_to_arraybuffer_1.default)(cargoesSerialized[0]));
        const cargoPayload = envelopedData_1.EnvelopedData.deserialize((0, buffer_to_arraybuffer_1.default)(cargo.payloadSerialized));
        expect(cargoPayload).toBeInstanceOf(envelopedData_1.SessionEnvelopedData);
        expect(cargoPayload.getRecipientKeyId()).toEqual(peerSessionKeyPair.sessionKey.keyId);
    });
    test('New ephemeral session key should be stored when using channel session', async () => {
        const channel = new StubGatewayChannel();
        const cargoesSerialized = await (0, _test_utils_1.asyncIterableToArray)(channel.generateCargoes((0, _test_utils_1.arrayToAsyncIterable)([
            {
                expiryDate: TOMORROW,
                message: MESSAGE,
            },
        ])));
        const cargo = await Cargo_1.default.deserialize((0, buffer_to_arraybuffer_1.default)(cargoesSerialized[0]));
        const cargoPayload = envelopedData_1.EnvelopedData.deserialize((0, buffer_to_arraybuffer_1.default)(cargo.payloadSerialized));
        const originatorKey = await cargoPayload.getOriginatorKey();
        await expect(KEY_STORES.privateKeyStore.retrieveSessionKey(originatorKey.keyId, await nodeCertificate.calculateSubjectPrivateAddress(), peerPrivateAddress)).toResolve();
    });
    test('Encryption options should be honored if present', async () => {
        const aesKeySize = 192;
        const channel = new StubGatewayChannel({ encryption: { aesKeySize } });
        const cargoesSerialized = await (0, _test_utils_1.asyncIterableToArray)(channel.generateCargoes((0, _test_utils_1.arrayToAsyncIterable)([
            {
                expiryDate: TOMORROW,
                message: MESSAGE,
            },
        ])));
        expect(await getCargoPayloadEncryptionAlgorithmId(cargoesSerialized[0])).toEqual(_test_utils_1.CRYPTO_OIDS.AES_CBC_192);
    });
    test('Cargo should be signed with the specified key', async () => {
        const channel = new StubGatewayChannel();
        const cargoesSerialized = await (0, _test_utils_1.asyncIterableToArray)(channel.generateCargoes((0, _test_utils_1.arrayToAsyncIterable)([
            {
                expiryDate: TOMORROW,
                message: MESSAGE,
            },
        ])));
        const cargo = await Cargo_1.default.deserialize((0, buffer_to_arraybuffer_1.default)(cargoesSerialized[0]));
        expect(nodeCertificate.isEqual(cargo.senderCertificate)).toBeTrue();
    });
    test('Signature options should be honored if present', async () => {
        const signatureOptions = { hashingAlgorithmName: 'SHA-384' };
        const channel = new StubGatewayChannel({ signature: signatureOptions });
        const cargoSerializeSpy = jest.spyOn(Cargo_1.default.prototype, 'serialize');
        await (0, _test_utils_1.asyncIterableToArray)(channel.generateCargoes((0, _test_utils_1.arrayToAsyncIterable)([
            {
                expiryDate: TOMORROW,
                message: MESSAGE,
            },
        ])));
        expect(cargoSerializeSpy).toBeCalledTimes(1);
        expect(cargoSerializeSpy).toBeCalledWith(expect.anything(), signatureOptions);
    });
    test('Cargo creation date should be 3 hours in the past', async () => {
        const channel = new StubGatewayChannel();
        const cargoesSerialized = await (0, _test_utils_1.asyncIterableToArray)(channel.generateCargoes((0, _test_utils_1.arrayToAsyncIterable)([
            {
                message: MESSAGE,
                expiryDate: TOMORROW,
            },
        ])));
        const cargo = await Cargo_1.default.deserialize((0, buffer_to_arraybuffer_1.default)(cargoesSerialized[0]));
        const expectedCreationDate = new Date();
        expectedCreationDate.setHours(expectedCreationDate.getHours() - 3);
        expect(cargo.creationDate.getTime()).toBeWithin(expectedCreationDate.getTime() - 5000, expectedCreationDate.getTime() + 5000);
    });
    test('Cargo TTL should be that of the message with the latest TTL', async () => {
        const channel = new StubGatewayChannel();
        const cargoesSerialized = await (0, _test_utils_1.asyncIterableToArray)(channel.generateCargoes((0, _test_utils_1.arrayToAsyncIterable)([
            { message: MESSAGE, expiryDate: TOMORROW },
            { message: MESSAGE, expiryDate: new Date() },
        ])));
        const cargo = await Cargo_1.default.deserialize((0, buffer_to_arraybuffer_1.default)(cargoesSerialized[0]));
        expect(cargo.expiryDate).toEqual(TOMORROW);
    });
    test('Cargo TTL should not exceed maximum RAMF TTL', async () => {
        const channel = new StubGatewayChannel();
        const now = new Date();
        const cargoesSerialized = await (0, _test_utils_1.asyncIterableToArray)(channel.generateCargoes((0, _test_utils_1.arrayToAsyncIterable)([
            {
                message: MESSAGE,
                expiryDate: (0, date_fns_1.addSeconds)(now, serialization_1.RAMF_MAX_TTL + 10),
            },
        ])));
        const cargo = await Cargo_1.default.deserialize((0, buffer_to_arraybuffer_1.default)(cargoesSerialized[0]));
        expect(cargo.ttl).toEqual(serialization_1.RAMF_MAX_TTL);
    });
    test('Zero cargoes should be output if there are zero messages', async () => {
        const channel = new StubGatewayChannel();
        const cargoesSerialized = await (0, _test_utils_1.asyncIterableToArray)(channel.generateCargoes((0, _test_utils_1.arrayToAsyncIterable)([])));
        expect(cargoesSerialized).toHaveLength(0);
    });
    test('Messages should be encapsulated into as few cargoes as possible', async () => {
        const channel = new StubGatewayChannel();
        const dummyParcel = await generateDummyParcel(peerPrivateAddress, peerSessionKeyPair.sessionKey, nodeCertificate);
        const dummyParcelSerialized = await dummyParcel.serialize(nodePrivateKey);
        const cargoesSerialized = await (0, _test_utils_1.asyncIterableToArray)(channel.generateCargoes((0, _test_utils_1.arrayToAsyncIterable)([
            { message: Buffer.from(dummyParcelSerialized), expiryDate: TOMORROW },
            { message: Buffer.from(dummyParcelSerialized), expiryDate: TOMORROW },
            { message: Buffer.from(dummyParcelSerialized), expiryDate: TOMORROW },
        ])));
        expect(cargoesSerialized).toHaveLength(1);
        const messageSet = await extractMessageSetFromCargo(cargoesSerialized[0]);
        expect(messageSet.messages.length).toEqual(3);
        expect(Array.from(messageSet.messages)).toEqual([
            dummyParcelSerialized,
            dummyParcelSerialized,
            dummyParcelSerialized,
        ]);
    });
    async function extractMessageSetFromCargo(cargoSerialized) {
        const cargo = await Cargo_1.default.deserialize((0, buffer_to_arraybuffer_1.default)(cargoSerialized));
        const { payload } = await cargo.unwrapPayload(peerSessionKeyPair.privateKey);
        return payload;
    }
    async function getCargoPayloadEncryptionAlgorithmId(cargoSerialized) {
        const cargo = await Cargo_1.default.deserialize((0, buffer_to_arraybuffer_1.default)(cargoSerialized));
        const cargoPayload = envelopedData_1.EnvelopedData.deserialize((0, buffer_to_arraybuffer_1.default)(cargo.payloadSerialized));
        const encryptedContentInfo = cargoPayload.pkijsEnvelopedData.encryptedContentInfo;
        return encryptedContentInfo.contentEncryptionAlgorithm.algorithmId;
    }
});
async function generateDummyParcel(recipientAddress, recipientSessionKey, finalSenderCertificate) {
    const serviceMessage = new ServiceMessage_1.default('a', Buffer.from('the payload'));
    const serviceMessageSerialized = await serviceMessage.serialize();
    const { envelopedData } = await envelopedData_1.SessionEnvelopedData.encrypt(serviceMessageSerialized, recipientSessionKey);
    const payloadSerialized = Buffer.from(envelopedData.serialize());
    return new Parcel_1.default(recipientAddress, finalSenderCertificate, payloadSerialized);
}
class StubGatewayChannel extends GatewayChannel_1.GatewayChannel {
    constructor(cryptoOptions = {}) {
        super(nodePrivateKey, nodeCertificate, peerPrivateAddress, peerPublicKey, KEY_STORES, cryptoOptions);
    }
    getOutboundRAMFAddress() {
        return StubGatewayChannel.OUTBOUND_RAMF_ADDRESS;
    }
}
StubGatewayChannel.OUTBOUND_RAMF_ADDRESS = '0deadbeef';
//# sourceMappingURL=GatewayChannel.spec.js.map