"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const date_fns_1 = require("date-fns");
const _test_utils_1 = require("../_test_utils");
const keys_1 = require("../crypto_wrappers/keys");
const testMocks_1 = require("../keyStores/testMocks");
const CertificationPath_1 = require("../pki/CertificationPath");
const issuance_1 = require("../pki/issuance");
const Gateway_1 = require("./Gateway");
const _test_utils_2 = require("./signatures/_test_utils");
let nodePrivateAddress;
let nodePrivateKey;
let nodeCertificate;
let nodeCertificateIssuer;
let nodeCertificateIssuerPrivateAddress;
beforeAll(async () => {
    const tomorrow = (0, date_fns_1.setMilliseconds)((0, date_fns_1.addDays)(new Date(), 1), 0);
    const issuerKeyPair = await (0, keys_1.generateRSAKeyPair)();
    nodeCertificateIssuer = (0, _test_utils_1.reSerializeCertificate)(await (0, issuance_1.issueGatewayCertificate)({
        issuerPrivateKey: issuerKeyPair.privateKey,
        subjectPublicKey: issuerKeyPair.publicKey,
        validityEndDate: tomorrow,
    }));
    nodeCertificateIssuerPrivateAddress =
        await nodeCertificateIssuer.calculateSubjectPrivateAddress();
    const nodeKeyPair = await (0, keys_1.generateRSAKeyPair)();
    nodePrivateKey = nodeKeyPair.privateKey;
    nodeCertificate = (0, _test_utils_1.reSerializeCertificate)(await (0, issuance_1.issueGatewayCertificate)({
        issuerCertificate: nodeCertificateIssuer,
        issuerPrivateKey: issuerKeyPair.privateKey,
        subjectPublicKey: nodeKeyPair.publicKey,
        validityEndDate: tomorrow,
    }));
    nodePrivateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(nodeKeyPair.publicKey);
});
const KEY_STORES = new testMocks_1.MockKeyStoreSet();
beforeEach(async () => {
    KEY_STORES.clear();
});
describe('getGSCVerifier', () => {
    test('Certificates from a different issuer should be ignored', async () => {
        const gateway = new StubGateway(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        await KEY_STORES.certificateStore.save(new CertificationPath_1.CertificationPath(nodeCertificate, []), nodeCertificateIssuerPrivateAddress);
        const verifier = await gateway.getGSCVerifier(`not-${nodeCertificateIssuerPrivateAddress}`, _test_utils_2.StubVerifier);
        expect(verifier.getTrustedCertificates()).toBeEmpty();
    });
    test('All certificates should be set as trusted', async () => {
        const gateway = new StubGateway(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        await KEY_STORES.certificateStore.save(new CertificationPath_1.CertificationPath(nodeCertificate, []), nodeCertificateIssuerPrivateAddress);
        const verifier = await gateway.getGSCVerifier(nodeCertificateIssuerPrivateAddress, _test_utils_2.StubVerifier);
        const trustedCertificates = verifier.getTrustedCertificates();
        expect(trustedCertificates).toHaveLength(1);
        expect(nodeCertificate.isEqual(trustedCertificates[0])).toBeTrue();
    });
});
class StubGateway extends Gateway_1.Gateway {
}
//# sourceMappingURL=Gateway.spec.js.map