"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const date_fns_1 = require("date-fns");
const _test_utils_1 = require("../../_test_utils");
const PrivateNodeRegistration_1 = require("../../bindings/gsc/PrivateNodeRegistration");
const PrivateNodeRegistrationAuthorization_1 = require("../../bindings/gsc/PrivateNodeRegistrationAuthorization");
const keys_1 = require("../../crypto_wrappers/keys");
const testMocks_1 = require("../../keyStores/testMocks");
const CargoCollectionAuthorization_1 = require("../../messages/CargoCollectionAuthorization");
const InvalidMessageError_1 = __importDefault(require("../../messages/InvalidMessageError"));
const issuance_1 = require("../../pki/issuance");
const SessionKeyPair_1 = require("../../SessionKeyPair");
const PrivatePublicGatewayChannel_1 = require("./PrivatePublicGatewayChannel");
let publicGatewayPrivateAddress;
let publicGatewayPublicKey;
let publicGatewayCertificate;
let privateGatewayPrivateAddress;
let privateGatewayKeyPair;
let privateGatewayPDCCertificate;
beforeAll(async () => {
    const nextYear = (0, date_fns_1.setMilliseconds)((0, date_fns_1.addDays)(new Date(), 360), 0);
    // Public gateway
    const publicGatewayKeyPair = await (0, keys_1.generateRSAKeyPair)();
    publicGatewayPublicKey = publicGatewayKeyPair.publicKey;
    publicGatewayPrivateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(publicGatewayPublicKey);
    publicGatewayCertificate = await (0, issuance_1.issueGatewayCertificate)({
        issuerPrivateKey: publicGatewayKeyPair.privateKey,
        subjectPublicKey: publicGatewayPublicKey,
        validityEndDate: nextYear,
    });
    // Private gateway
    privateGatewayKeyPair = await (0, keys_1.generateRSAKeyPair)();
    privateGatewayPDCCertificate = (0, _test_utils_1.reSerializeCertificate)(await (0, issuance_1.issueGatewayCertificate)({
        issuerCertificate: publicGatewayCertificate,
        issuerPrivateKey: publicGatewayKeyPair.privateKey,
        subjectPublicKey: privateGatewayKeyPair.publicKey,
        validityEndDate: nextYear,
    }));
    privateGatewayPrivateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(privateGatewayKeyPair.publicKey);
});
let publicGatewaySessionKeyPair;
beforeAll(async () => {
    publicGatewaySessionKeyPair = await SessionKeyPair_1.SessionKeyPair.generate();
});
const KEY_STORES = new testMocks_1.MockKeyStoreSet();
beforeEach(async () => {
    await KEY_STORES.publicKeyStore.saveIdentityKey(await publicGatewayCertificate.getPublicKey());
    await KEY_STORES.publicKeyStore.saveSessionKey(publicGatewaySessionKeyPair.sessionKey, publicGatewayPrivateAddress, new Date());
});
afterEach(() => {
    KEY_STORES.clear();
});
const PUBLIC_GATEWAY_PUBLIC_ADDRESS = 'example.com';
let channel;
beforeEach(() => {
    channel = new PrivatePublicGatewayChannel_1.PrivatePublicGatewayChannel(privateGatewayKeyPair.privateKey, privateGatewayPDCCertificate, publicGatewayPrivateAddress, publicGatewayPublicKey, PUBLIC_GATEWAY_PUBLIC_ADDRESS, KEY_STORES, {});
});
test('getOutboundRAMFAddress should return public address of public gateway', () => {
    expect(channel.getOutboundRAMFAddress()).toEqual(`https://${PUBLIC_GATEWAY_PUBLIC_ADDRESS}`);
});
describe('Endpoint registration', () => {
    const GATEWAY_DATA = (0, _test_utils_1.arrayBufferFrom)('the gw data');
    const EXPIRY_DATE = (0, date_fns_1.setMilliseconds)((0, date_fns_1.addDays)(new Date(), 1), 0);
    describe('authorizeEndpointRegistration', () => {
        test('Gateway data should be honoured', async () => {
            const authorizationSerialized = await channel.authorizeEndpointRegistration(GATEWAY_DATA, EXPIRY_DATE);
            const authorization = await PrivateNodeRegistrationAuthorization_1.PrivateNodeRegistrationAuthorization.deserialize(authorizationSerialized, privateGatewayKeyPair.publicKey);
            expect(authorization.gatewayData).toEqual(GATEWAY_DATA);
        });
        test('Expiry date should be honoured', async () => {
            const authorizationSerialized = await channel.authorizeEndpointRegistration(GATEWAY_DATA, EXPIRY_DATE);
            const authorization = await PrivateNodeRegistrationAuthorization_1.PrivateNodeRegistrationAuthorization.deserialize(authorizationSerialized, privateGatewayKeyPair.publicKey);
            expect(authorization.expiryDate).toEqual(EXPIRY_DATE);
        });
    });
    describe('verifyEndpointRegistrationAuthorization', () => {
        test('Error should be thrown if authorization is invalid', async () => {
            const authorization = new PrivateNodeRegistrationAuthorization_1.PrivateNodeRegistrationAuthorization(EXPIRY_DATE, GATEWAY_DATA);
            const differentKeyPair = await (0, keys_1.generateRSAKeyPair)();
            const authorizationSerialized = await authorization.serialize(differentKeyPair.privateKey);
            await expect(channel.verifyEndpointRegistrationAuthorization(authorizationSerialized)).rejects.toBeInstanceOf(InvalidMessageError_1.default);
        });
        test('Gateway data should be returned if signed with right key', async () => {
            const authorizationSerialized = await channel.authorizeEndpointRegistration(GATEWAY_DATA, EXPIRY_DATE);
            await expect(channel.verifyEndpointRegistrationAuthorization(authorizationSerialized)).resolves.toEqual(GATEWAY_DATA);
        });
    });
    describe('registerEndpoint', () => {
        let endpointPublicKey;
        beforeAll(async () => {
            const endpointKeyPair = await (0, keys_1.generateRSAKeyPair)();
            endpointPublicKey = endpointKeyPair.publicKey;
        });
        test('Endpoint certificate should be issued by public gateway', async () => {
            const registrationSerialized = await channel.registerEndpoint(endpointPublicKey);
            const registration = await PrivateNodeRegistration_1.PrivateNodeRegistration.deserialize(registrationSerialized);
            const endpointCertificate = (0, _test_utils_1.reSerializeCertificate)(registration.privateNodeCertificate);
            await expect(endpointCertificate.getCertificationPath([], [privateGatewayPDCCertificate])).resolves.toHaveLength(2);
        });
        test('Endpoint certificate should be valid starting now', async () => {
            const preRegistrationDate = (0, date_fns_1.setMilliseconds)(new Date(), 0);
            const registrationSerialized = await channel.registerEndpoint(endpointPublicKey);
            const registration = await PrivateNodeRegistration_1.PrivateNodeRegistration.deserialize(registrationSerialized);
            expect(registration.privateNodeCertificate.startDate).toBeAfterOrEqualTo(preRegistrationDate);
            expect(registration.privateNodeCertificate.startDate).toBeBeforeOrEqualTo(new Date());
        });
        test('Endpoint certificate should be valid for 6 months', async () => {
            const preRegistrationDate = (0, date_fns_1.setMilliseconds)(new Date(), 0);
            const registrationSerialized = await channel.registerEndpoint(endpointPublicKey);
            const registration = await PrivateNodeRegistration_1.PrivateNodeRegistration.deserialize(registrationSerialized);
            expect(registration.privateNodeCertificate.expiryDate).toBeAfterOrEqualTo((0, date_fns_1.addMonths)(preRegistrationDate, 6));
            expect(registration.privateNodeCertificate.expiryDate).toBeBeforeOrEqualTo((0, date_fns_1.addMonths)(new Date(), 6));
        });
        test('Endpoint certificate should honor subject public key', async () => {
            const registrationSerialized = await channel.registerEndpoint(endpointPublicKey);
            const registration = await PrivateNodeRegistration_1.PrivateNodeRegistration.deserialize(registrationSerialized);
            await expect((0, keys_1.derSerializePublicKey)(await registration.privateNodeCertificate.getPublicKey())).resolves.toEqual(await (0, keys_1.derSerializePublicKey)(endpointPublicKey));
        });
        test('Gateway certificate should be included in registration', async () => {
            const registrationSerialized = await channel.registerEndpoint(endpointPublicKey);
            const registration = await PrivateNodeRegistration_1.PrivateNodeRegistration.deserialize(registrationSerialized);
            expect(registration.gatewayCertificate.isEqual(privateGatewayPDCCertificate)).toBeTrue();
        });
        test('Session key should be absent from registration', async () => {
            const registrationSerialized = await channel.registerEndpoint(endpointPublicKey);
            const registration = await PrivateNodeRegistration_1.PrivateNodeRegistration.deserialize(registrationSerialized);
            expect(registration.sessionKey).toBeNull();
        });
    });
});
describe('generateCCA', () => {
    test('Recipient should be public gateway', async () => {
        const ccaSerialized = await channel.generateCCA();
        const cca = await CargoCollectionAuthorization_1.CargoCollectionAuthorization.deserialize(ccaSerialized);
        expect(cca.recipientAddress).toEqual(`https://${PUBLIC_GATEWAY_PUBLIC_ADDRESS}`);
    });
    test('Creation date should be 90 minutes in the past to tolerate clock drift', async () => {
        const ccaSerialized = await channel.generateCCA();
        const cca = await CargoCollectionAuthorization_1.CargoCollectionAuthorization.deserialize(ccaSerialized);
        const now = new Date();
        expect(cca.creationDate).toBeBefore((0, date_fns_1.subMinutes)(now, 90));
        expect(cca.creationDate).toBeAfter((0, date_fns_1.subMinutes)(now, 92));
    });
    test('Expiry date should be 14 days in the future', async () => {
        const ccaSerialized = await channel.generateCCA();
        const cca = await CargoCollectionAuthorization_1.CargoCollectionAuthorization.deserialize(ccaSerialized);
        const now = new Date();
        expect(cca.expiryDate).toBeAfter((0, date_fns_1.addDays)(now, 13));
        expect(cca.expiryDate).toBeBefore((0, date_fns_1.addDays)(now, 14));
    });
    test('Sender should be PDC certificate of private gateway', async () => {
        const ccaSerialized = await channel.generateCCA();
        const cca = await CargoCollectionAuthorization_1.CargoCollectionAuthorization.deserialize(ccaSerialized);
        expect(cca.senderCertificate.isEqual(privateGatewayPDCCertificate)).toBeTrue();
    });
    test('Sender certificate chain should be empty', async () => {
        const ccaSerialized = await channel.generateCCA();
        const cca = await CargoCollectionAuthorization_1.CargoCollectionAuthorization.deserialize(ccaSerialized);
        expect(cca.senderCaCertificateChain).toEqual([]);
    });
    describe('Cargo Delivery Authorization', () => {
        test('Subject public key should be that of the public gateway', async () => {
            const ccaSerialized = await channel.generateCCA();
            const cargoDeliveryAuthorization = await extractCDA(ccaSerialized);
            expect(cargoDeliveryAuthorization.isEqual(publicGatewayCertificate)).toBeFalse();
            await expect((0, keys_1.derSerializePublicKey)(await cargoDeliveryAuthorization.getPublicKey())).resolves.toEqual(await (0, keys_1.derSerializePublicKey)(await publicGatewayCertificate.getPublicKey()));
        });
        test('Certificate should be valid for 14 days', async () => {
            const ccaSerialized = await channel.generateCCA();
            const cargoDeliveryAuthorization = await extractCDA(ccaSerialized);
            expect(cargoDeliveryAuthorization.expiryDate).toBeAfter((0, date_fns_1.addDays)(new Date(), 13));
            expect(cargoDeliveryAuthorization.expiryDate).toBeBefore((0, date_fns_1.addDays)(new Date(), 14));
        });
        test('Issuer should be private gateway', async () => {
            const ccaSerialized = await channel.generateCCA();
            const cargoDeliveryAuthorization = await extractCDA(ccaSerialized);
            const cdaIssuer = await KEY_STORES.certificateStore.retrieveLatest(privateGatewayPrivateAddress, privateGatewayPrivateAddress);
            await expect(cargoDeliveryAuthorization.getCertificationPath([], [cdaIssuer.leafCertificate])).toResolve();
        });
        async function extractCDA(ccaSerialized) {
            const cca = await CargoCollectionAuthorization_1.CargoCollectionAuthorization.deserialize(ccaSerialized);
            const { payload: ccr } = await cca.unwrapPayload(publicGatewaySessionKeyPair.privateKey);
            return ccr.cargoDeliveryAuthorization;
        }
    });
});
//# sourceMappingURL=PrivatePublicGatewayChannel.spec.js.map