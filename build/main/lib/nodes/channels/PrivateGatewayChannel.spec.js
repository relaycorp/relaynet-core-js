"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const date_fns_1 = require("date-fns");
const keys_1 = require("../../crypto_wrappers/keys");
const testMocks_1 = require("../../keyStores/testMocks");
const CertificationPath_1 = require("../../pki/CertificationPath");
const issuance_1 = require("../../pki/issuance");
const PrivateGatewayChannel_1 = require("./PrivateGatewayChannel");
let publicGatewayPrivateAddress;
let publicGatewayPublicKey;
let publicGatewayCertificate;
beforeAll(async () => {
    const tomorrow = (0, date_fns_1.setMilliseconds)((0, date_fns_1.addDays)(new Date(), 1), 0);
    // Public gateway
    const publicGatewayKeyPair = await (0, keys_1.generateRSAKeyPair)();
    publicGatewayPublicKey = publicGatewayKeyPair.publicKey;
    publicGatewayPrivateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(publicGatewayPublicKey);
    publicGatewayCertificate = await (0, issuance_1.issueGatewayCertificate)({
        issuerPrivateKey: publicGatewayKeyPair.privateKey,
        subjectPublicKey: publicGatewayPublicKey,
        validityEndDate: tomorrow,
    });
});
const KEY_STORES = new testMocks_1.MockKeyStoreSet();
let privateGatewayPrivateAddress;
let privateGatewayPrivateKey;
let privateGatewayPDCCertificate;
beforeEach(async () => {
    const { privateKey, publicKey, privateAddress } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();
    // Private gateway
    privateGatewayPrivateKey = privateKey;
    privateGatewayPDCCertificate = await (0, issuance_1.issueGatewayCertificate)({
        issuerCertificate: publicGatewayCertificate,
        issuerPrivateKey: privateKey,
        subjectPublicKey: publicKey,
        validityEndDate: publicGatewayCertificate.expiryDate,
    });
    privateGatewayPrivateAddress = privateAddress;
});
afterEach(() => {
    KEY_STORES.clear();
});
describe('getOrCreateCDAIssuer', () => {
    test('Certificate should be generated if none exists', async () => {
        await expect(retrieveCDAIssuer()).resolves.toBeNull();
        const channel = new StubPrivateGatewayChannel();
        const issuer = await channel.getOrCreateCDAIssuer();
        await expect(retrieveCDAIssuer()).resolves.toSatisfy((c) => c.isEqual(issuer));
    });
    test('Certificate be regenerated if latest expires in 90 days', async () => {
        const cutoffDate = (0, date_fns_1.addDays)(new Date(), 90);
        const expiringIssuer = await (0, issuance_1.issueGatewayCertificate)({
            subjectPublicKey: await (0, keys_1.getRSAPublicKeyFromPrivate)(privateGatewayPrivateKey),
            issuerPrivateKey: privateGatewayPrivateKey,
            validityEndDate: (0, date_fns_1.subSeconds)(cutoffDate, 1),
        });
        await saveCDAIssuer(expiringIssuer);
        const channel = new StubPrivateGatewayChannel();
        const issuer = await channel.getOrCreateCDAIssuer();
        const issuerRetrieved = await retrieveCDAIssuer();
        expect(expiringIssuer.isEqual(issuerRetrieved)).toBeFalse();
        expect(issuer.isEqual(issuerRetrieved));
    });
    test('Existing certificate should be reused if it will be valid for 90+ days', async () => {
        const channel = new StubPrivateGatewayChannel();
        const originalIssuer = await channel.getOrCreateCDAIssuer();
        const latestIssuer = await channel.getOrCreateCDAIssuer();
        expect(latestIssuer.isEqual(originalIssuer)).toBeTrue();
    });
    test('Subject key should be that of private gateway', async () => {
        const channel = new StubPrivateGatewayChannel();
        const issuer = await channel.getOrCreateCDAIssuer();
        await expect((0, keys_1.derSerializePublicKey)(await issuer.getPublicKey())).resolves.toEqual(await (0, keys_1.derSerializePublicKey)(await (0, keys_1.getRSAPublicKeyFromPrivate)(privateGatewayPrivateKey)));
    });
    test('Certificate should be self-issued', async () => {
        const channel = new StubPrivateGatewayChannel();
        const issuer = await channel.getOrCreateCDAIssuer();
        await expect(issuer.calculateSubjectPrivateAddress()).resolves.toEqual(privateGatewayPrivateAddress);
    });
    test('Certificate should be valid from 90 minutes in the past', async () => {
        const channel = new StubPrivateGatewayChannel();
        const issuer = await channel.getOrCreateCDAIssuer();
        const expectedStartDate = (0, date_fns_1.subMinutes)(new Date(), 90);
        expect(issuer.startDate).toBeAfter((0, date_fns_1.subSeconds)(expectedStartDate, 5));
        expect(issuer.startDate).toBeBefore(expectedStartDate);
    });
    test('Certificate should expire in 180 days when generated', async () => {
        const channel = new StubPrivateGatewayChannel();
        const issuer = await channel.getOrCreateCDAIssuer();
        const expectedExpiryDate = (0, date_fns_1.addDays)(new Date(), 180);
        expect(issuer.expiryDate).toBeBefore(expectedExpiryDate);
        expect(issuer.expiryDate).toBeAfter((0, date_fns_1.subSeconds)(expectedExpiryDate, 5));
    });
    async function retrieveCDAIssuer() {
        const issuerPath = await KEY_STORES.certificateStore.retrieveLatest(privateGatewayPrivateAddress, privateGatewayPrivateAddress);
        return issuerPath?.leafCertificate ?? null;
    }
    async function saveCDAIssuer(cdaIssuer) {
        await KEY_STORES.certificateStore.save(new CertificationPath_1.CertificationPath(cdaIssuer, []), await cdaIssuer.calculateSubjectPrivateAddress());
    }
});
describe('getCDAIssuers', () => {
    test('Nothing should be returned if there are no issuers', async () => {
        const channel = new StubPrivateGatewayChannel();
        await expect(channel.getCDAIssuers()).resolves.toHaveLength(0);
    });
    test('Other subjects should be ignored', async () => {
        const differentSubjectKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const differentSubjectCertificate = await (0, issuance_1.issueGatewayCertificate)({
            issuerCertificate: privateGatewayPDCCertificate,
            issuerPrivateKey: privateGatewayPrivateKey,
            subjectPublicKey: differentSubjectKeyPair.publicKey,
            validityEndDate: privateGatewayPDCCertificate.expiryDate,
        });
        await KEY_STORES.certificateStore.save(new CertificationPath_1.CertificationPath(differentSubjectCertificate, []), privateGatewayPrivateAddress);
        const channel = new StubPrivateGatewayChannel();
        await expect(channel.getCDAIssuers()).resolves.toHaveLength(0);
    });
    test('Other issuers should be ignored', async () => {
        await KEY_STORES.certificateStore.save(new CertificationPath_1.CertificationPath(privateGatewayPDCCertificate, []), `not-${privateGatewayPrivateAddress}`);
        const channel = new StubPrivateGatewayChannel();
        await expect(channel.getCDAIssuers()).resolves.toHaveLength(0);
    });
    test('CDA issuers should be returned', async () => {
        const channel = new StubPrivateGatewayChannel();
        const issuer = await channel.getOrCreateCDAIssuer();
        const issuers = await channel.getCDAIssuers();
        expect(issuers).toHaveLength(1);
        expect(issuers[0].isEqual(issuer)).toBeTrue();
    });
});
class StubPrivateGatewayChannel extends PrivateGatewayChannel_1.PrivateGatewayChannel {
    constructor(cryptoOptions = {}) {
        super(privateGatewayPrivateKey, privateGatewayPDCCertificate, publicGatewayPrivateAddress, publicGatewayPublicKey, KEY_STORES, cryptoOptions);
    }
    getOutboundRAMFAddress() {
        throw new Error('not implemented');
    }
}
//# sourceMappingURL=PrivateGatewayChannel.spec.js.map