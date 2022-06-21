"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const date_fns_1 = require("date-fns");
const _test_utils_1 = require("../_test_utils");
const PrivateNodeRegistrationRequest_1 = require("../bindings/gsc/PrivateNodeRegistrationRequest");
const keys_1 = require("../crypto_wrappers/keys");
const testMocks_1 = require("../keyStores/testMocks");
const CertificationPath_1 = require("../pki/CertificationPath");
const issuance_1 = require("../pki/issuance");
const SessionKeyPair_1 = require("../SessionKeyPair");
const errors_1 = require("./errors");
const PrivateGateway_1 = require("./PrivateGateway");
const PUBLIC_GATEWAY_PUBLIC_ADDRESS = 'example.com';
let publicGatewayPrivateAddress;
let publicGatewayPublicKey;
let publicGatewayCertificate;
let privateGatewayPrivateAddress;
let privateGatewayPrivateKey;
let privateGatewayPDCCertificate;
beforeAll(async () => {
    const tomorrow = (0, date_fns_1.setMilliseconds)((0, date_fns_1.addDays)(new Date(), 1), 0);
    // Public gateway
    const publicGatewayKeyPair = await (0, keys_1.generateRSAKeyPair)();
    publicGatewayPublicKey = publicGatewayKeyPair.publicKey;
    publicGatewayPrivateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(publicGatewayPublicKey);
    publicGatewayCertificate = (0, _test_utils_1.reSerializeCertificate)(await (0, issuance_1.issueGatewayCertificate)({
        issuerPrivateKey: publicGatewayKeyPair.privateKey,
        subjectPublicKey: publicGatewayPublicKey,
        validityEndDate: tomorrow,
    }));
    // Private gateway
    const privateGatewayKeyPair = await (0, keys_1.generateRSAKeyPair)();
    privateGatewayPrivateKey = privateGatewayKeyPair.privateKey;
    privateGatewayPrivateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(privateGatewayKeyPair.publicKey);
    privateGatewayPDCCertificate = (0, _test_utils_1.reSerializeCertificate)(await (0, issuance_1.issueGatewayCertificate)({
        issuerCertificate: publicGatewayCertificate,
        issuerPrivateKey: publicGatewayKeyPair.privateKey,
        subjectPublicKey: privateGatewayKeyPair.publicKey,
        validityEndDate: tomorrow,
    }));
});
const KEY_STORES = new testMocks_1.MockKeyStoreSet();
afterEach(() => {
    KEY_STORES.clear();
});
describe('requestPublicGatewayRegistration', () => {
    const AUTHORIZATION_SERIALIZED = (0, _test_utils_1.arrayBufferFrom)('Go ahead');
    test('Registration authorization should be honoured', async () => {
        const privateGateway = new PrivateGateway_1.PrivateGateway(privateGatewayPrivateAddress, privateGatewayPrivateKey, KEY_STORES, {});
        const requestSerialized = await privateGateway.requestPublicGatewayRegistration(AUTHORIZATION_SERIALIZED);
        const request = await PrivateNodeRegistrationRequest_1.PrivateNodeRegistrationRequest.deserialize(requestSerialized);
        expect(request.pnraSerialized).toEqual(AUTHORIZATION_SERIALIZED);
    });
    test('Public key should be honoured', async () => {
        const privateGateway = new PrivateGateway_1.PrivateGateway(privateGatewayPrivateAddress, privateGatewayPrivateKey, KEY_STORES, {});
        const requestSerialized = await privateGateway.requestPublicGatewayRegistration(AUTHORIZATION_SERIALIZED);
        const request = await PrivateNodeRegistrationRequest_1.PrivateNodeRegistrationRequest.deserialize(requestSerialized);
        await expect((0, keys_1.derSerializePublicKey)(request.privateNodePublicKey)).resolves.toEqual(await (0, keys_1.derSerializePublicKey)(await (0, keys_1.getRSAPublicKeyFromPrivate)(privateGatewayPrivateKey)));
    });
});
describe('savePublicGatewayChannel', () => {
    let publicGatewaySessionPublicKey;
    beforeAll(async () => {
        const publicGatewaySessionKeyPair = await SessionKeyPair_1.SessionKeyPair.generate();
        publicGatewaySessionPublicKey = publicGatewaySessionKeyPair.sessionKey;
    });
    test('Registration should be refused if public gateway did not issue authorization', async () => {
        const privateGateway = new PrivateGateway_1.PrivateGateway(privateGatewayPrivateAddress, privateGatewayPrivateKey, KEY_STORES, {});
        await expect(privateGateway.savePublicGatewayChannel(privateGatewayPDCCertificate, privateGatewayPDCCertificate, // Invalid
        publicGatewaySessionPublicKey)).rejects.toThrowWithMessage(errors_1.NodeError, 'Delivery authorization was not issued by public gateway');
    });
    test('Delivery authorisation should be stored', async () => {
        const privateGateway = new PrivateGateway_1.PrivateGateway(privateGatewayPrivateAddress, privateGatewayPrivateKey, KEY_STORES, {});
        await privateGateway.savePublicGatewayChannel(privateGatewayPDCCertificate, publicGatewayCertificate, publicGatewaySessionPublicKey);
        const path = await KEY_STORES.certificateStore.retrieveLatest(privateGatewayPrivateAddress, publicGatewayPrivateAddress);
        expect(path.leafCertificate.isEqual(privateGatewayPDCCertificate));
        expect(path.certificateAuthorities).toHaveLength(0);
    });
    test('Public key of public gateway should be stored', async () => {
        const privateGateway = new PrivateGateway_1.PrivateGateway(privateGatewayPrivateAddress, privateGatewayPrivateKey, KEY_STORES, {});
        await privateGateway.savePublicGatewayChannel(privateGatewayPDCCertificate, publicGatewayCertificate, publicGatewaySessionPublicKey);
        const publicGatewayPublicKeyRetrieved = await KEY_STORES.publicKeyStore.retrieveIdentityKey(publicGatewayPrivateAddress);
        expect(publicGatewayPublicKeyRetrieved).toBeTruthy();
        await expect((0, keys_1.derSerializePublicKey)(publicGatewayPublicKeyRetrieved)).resolves.toEqual(await (0, keys_1.derSerializePublicKey)(publicGatewayPublicKey));
    });
    test('Session public key of public gateway should be stored', async () => {
        const privateGateway = new PrivateGateway_1.PrivateGateway(privateGatewayPrivateAddress, privateGatewayPrivateKey, KEY_STORES, {});
        await privateGateway.savePublicGatewayChannel(privateGatewayPDCCertificate, publicGatewayCertificate, publicGatewaySessionPublicKey);
        const keyData = KEY_STORES.publicKeyStore.sessionKeys[publicGatewayPrivateAddress];
        expect(keyData.publicKeyDer).toEqual(await (0, keys_1.derSerializePublicKey)(publicGatewaySessionPublicKey.publicKey));
        expect(keyData.publicKeyId).toEqual(publicGatewaySessionPublicKey.keyId);
        expect(keyData.publicKeyCreationTime).toBeBeforeOrEqualTo(new Date());
        expect(keyData.publicKeyCreationTime).toBeAfter((0, date_fns_1.subSeconds)(new Date(), 10));
    });
});
describe('retrievePublicGatewayChannel', () => {
    test('Null should be returned if public gateway public key is not found', async () => {
        await KEY_STORES.certificateStore.save(new CertificationPath_1.CertificationPath(privateGatewayPDCCertificate, []), publicGatewayPrivateAddress);
        const privateGateway = new PrivateGateway_1.PrivateGateway(privateGatewayPrivateAddress, privateGatewayPrivateKey, KEY_STORES, {});
        await expect(privateGateway.retrievePublicGatewayChannel(publicGatewayPrivateAddress, PUBLIC_GATEWAY_PUBLIC_ADDRESS)).resolves.toBeNull();
    });
    test('Null should be returned if delivery authorization is not found', async () => {
        await KEY_STORES.publicKeyStore.saveIdentityKey(publicGatewayPublicKey);
        const privateGateway = new PrivateGateway_1.PrivateGateway(privateGatewayPrivateAddress, privateGatewayPrivateKey, KEY_STORES, {});
        await expect(privateGateway.retrievePublicGatewayChannel(publicGatewayPrivateAddress, PUBLIC_GATEWAY_PUBLIC_ADDRESS)).resolves.toBeNull();
    });
    test('Channel should be returned if it exists', async () => {
        await KEY_STORES.certificateStore.save(new CertificationPath_1.CertificationPath(privateGatewayPDCCertificate, []), publicGatewayPrivateAddress);
        await KEY_STORES.publicKeyStore.saveIdentityKey(publicGatewayPublicKey);
        const privateGateway = new PrivateGateway_1.PrivateGateway(privateGatewayPrivateAddress, privateGatewayPrivateKey, KEY_STORES, {});
        const channel = await privateGateway.retrievePublicGatewayChannel(publicGatewayPrivateAddress, PUBLIC_GATEWAY_PUBLIC_ADDRESS);
        expect(channel.publicGatewayPublicAddress).toEqual(PUBLIC_GATEWAY_PUBLIC_ADDRESS);
        expect(channel.nodeDeliveryAuth.isEqual(privateGatewayPDCCertificate)).toBeTrue();
        expect(channel.peerPrivateAddress).toEqual(publicGatewayPrivateAddress);
        await expect((0, keys_1.derSerializePublicKey)(channel.peerPublicKey)).resolves.toEqual(await (0, keys_1.derSerializePublicKey)(publicGatewayPublicKey));
    });
    test('Crypto options should be passed', async () => {
        await KEY_STORES.certificateStore.save(new CertificationPath_1.CertificationPath(privateGatewayPDCCertificate, []), publicGatewayPrivateAddress);
        await KEY_STORES.publicKeyStore.saveIdentityKey(publicGatewayPublicKey);
        const cryptoOptions = { encryption: { aesKeySize: 256 } };
        const privateGateway = new PrivateGateway_1.PrivateGateway(privateGatewayPrivateAddress, privateGatewayPrivateKey, KEY_STORES, cryptoOptions);
        const channel = await privateGateway.retrievePublicGatewayChannel(publicGatewayPrivateAddress, PUBLIC_GATEWAY_PUBLIC_ADDRESS);
        expect(channel?.cryptoOptions).toEqual(cryptoOptions);
    });
});
//# sourceMappingURL=PrivateGateway.spec.js.map