"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const _test_utils_1 = require("../../_test_utils");
const keys_1 = require("../../crypto_wrappers/keys");
const InvalidMessageError_1 = __importDefault(require("../../messages/InvalidMessageError"));
const Parcel_1 = __importDefault(require("../../messages/Parcel"));
const issuance_1 = require("../../pki/issuance");
const RAMFSyntaxError_1 = __importDefault(require("../../ramf/RAMFSyntaxError"));
const ParcelCollection_1 = require("./ParcelCollection");
const PARCEL_SERIALIZED = (0, _test_utils_1.arrayBufferFrom)('the parcel serialized');
let pdaGranteeKeyPair;
let pdaCertificate;
let recipientCertificate;
let gatewayCertificate;
beforeAll(async () => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const caKeyPair = await (0, keys_1.generateRSAKeyPair)();
    gatewayCertificate = (0, _test_utils_1.reSerializeCertificate)(await (0, issuance_1.issueGatewayCertificate)({
        issuerPrivateKey: caKeyPair.privateKey,
        subjectPublicKey: caKeyPair.publicKey,
        validityEndDate: tomorrow,
    }));
    const recipientKeyPair = await (0, keys_1.generateRSAKeyPair)();
    recipientCertificate = (0, _test_utils_1.reSerializeCertificate)(await (0, issuance_1.issueEndpointCertificate)({
        issuerCertificate: gatewayCertificate,
        issuerPrivateKey: caKeyPair.privateKey,
        subjectPublicKey: recipientKeyPair.publicKey,
        validityEndDate: tomorrow,
    }));
    pdaGranteeKeyPair = await (0, keys_1.generateRSAKeyPair)();
    pdaCertificate = (0, _test_utils_1.reSerializeCertificate)(await (0, issuance_1.issueDeliveryAuthorization)({
        issuerCertificate: recipientCertificate,
        issuerPrivateKey: recipientKeyPair.privateKey,
        subjectPublicKey: pdaGranteeKeyPair.publicKey,
        validityEndDate: tomorrow,
    }));
});
test('Parcel serialized should be honored', () => {
    const collection = new ParcelCollection_1.ParcelCollection(PARCEL_SERIALIZED, [gatewayCertificate], jest.fn());
    (0, _test_utils_1.expectArrayBuffersToEqual)(PARCEL_SERIALIZED, collection.parcelSerialized);
});
test('Trusted certificates should be honored', () => {
    const collection = new ParcelCollection_1.ParcelCollection(PARCEL_SERIALIZED, [gatewayCertificate], jest.fn());
    expect(collection.trustedCertificates).toEqual([gatewayCertificate]);
});
test('ACK callback should be honored', async () => {
    const ackCallback = jest.fn();
    const collection = new ParcelCollection_1.ParcelCollection(PARCEL_SERIALIZED, [gatewayCertificate], ackCallback);
    await collection.ack();
    expect(ackCallback).toBeCalled();
});
describe('deserializeAndValidateParcel', () => {
    test('Malformed parcels should be refused', async () => {
        const collection = new ParcelCollection_1.ParcelCollection((0, _test_utils_1.arrayBufferFrom)('invalid'), [gatewayCertificate], jest.fn());
        await expect(collection.deserializeAndValidateParcel()).rejects.toBeInstanceOf(RAMFSyntaxError_1.default);
    });
    test('Parcels bound for public endpoints should be refused', async () => {
        const parcel = new Parcel_1.default('https://example.com', pdaCertificate, Buffer.from([]), {
            senderCaCertificateChain: [gatewayCertificate],
        });
        const collection = new ParcelCollection_1.ParcelCollection(await parcel.serialize(pdaGranteeKeyPair.privateKey), [gatewayCertificate], jest.fn());
        await expect(collection.deserializeAndValidateParcel()).rejects.toBeInstanceOf(InvalidMessageError_1.default);
    });
    test('Parcels from unauthorized senders should be refused', async () => {
        const unauthorizedSenderCertificate = await (0, _test_utils_1.generateStubCert)({
            issuerPrivateKey: pdaGranteeKeyPair.privateKey,
            subjectPublicKey: pdaGranteeKeyPair.publicKey,
        });
        const parcel = new Parcel_1.default('0deadbeef', unauthorizedSenderCertificate, Buffer.from([]));
        const collection = new ParcelCollection_1.ParcelCollection(await parcel.serialize(pdaGranteeKeyPair.privateKey), [gatewayCertificate], jest.fn());
        await expect(collection.deserializeAndValidateParcel()).rejects.toBeInstanceOf(InvalidMessageError_1.default);
    });
    test('Valid parcels should be returned', async () => {
        const parcel = new Parcel_1.default(await recipientCertificate.calculateSubjectPrivateAddress(), pdaCertificate, Buffer.from([]), { senderCaCertificateChain: [recipientCertificate] });
        const collection = new ParcelCollection_1.ParcelCollection(await parcel.serialize(pdaGranteeKeyPair.privateKey), [gatewayCertificate], jest.fn());
        const parcelDeserialized = await collection.deserializeAndValidateParcel();
        expect(parcelDeserialized.id).toEqual(parcel.id);
    });
});
//# sourceMappingURL=ParcelCollection.spec.js.map