import { addDays, setMilliseconds } from 'date-fns';
import { reSerializeCertificate } from '../_test_utils';
import { generateRSAKeyPair, getPrivateAddressFromIdentityKey } from '../crypto_wrappers/keys';
import { MockKeyStoreSet } from '../keyStores/testMocks';
import { CertificationPath } from '../pki/CertificationPath';
import { issueGatewayCertificate } from '../pki/issuance';
import { Gateway } from './Gateway';
import { StubVerifier } from './signatures/_test_utils';
let nodePrivateAddress;
let nodePrivateKey;
let nodeCertificate;
let nodeCertificateIssuer;
let nodeCertificateIssuerPrivateAddress;
beforeAll(async () => {
    const tomorrow = setMilliseconds(addDays(new Date(), 1), 0);
    const issuerKeyPair = await generateRSAKeyPair();
    nodeCertificateIssuer = reSerializeCertificate(await issueGatewayCertificate({
        issuerPrivateKey: issuerKeyPair.privateKey,
        subjectPublicKey: issuerKeyPair.publicKey,
        validityEndDate: tomorrow,
    }));
    nodeCertificateIssuerPrivateAddress =
        await nodeCertificateIssuer.calculateSubjectPrivateAddress();
    const nodeKeyPair = await generateRSAKeyPair();
    nodePrivateKey = nodeKeyPair.privateKey;
    nodeCertificate = reSerializeCertificate(await issueGatewayCertificate({
        issuerCertificate: nodeCertificateIssuer,
        issuerPrivateKey: issuerKeyPair.privateKey,
        subjectPublicKey: nodeKeyPair.publicKey,
        validityEndDate: tomorrow,
    }));
    nodePrivateAddress = await getPrivateAddressFromIdentityKey(nodeKeyPair.publicKey);
});
const KEY_STORES = new MockKeyStoreSet();
beforeEach(async () => {
    KEY_STORES.clear();
});
describe('getGSCVerifier', () => {
    test('Certificates from a different issuer should be ignored', async () => {
        const gateway = new StubGateway(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        await KEY_STORES.certificateStore.save(new CertificationPath(nodeCertificate, []), nodeCertificateIssuerPrivateAddress);
        const verifier = await gateway.getGSCVerifier(`not-${nodeCertificateIssuerPrivateAddress}`, StubVerifier);
        expect(verifier.getTrustedCertificates()).toBeEmpty();
    });
    test('All certificates should be set as trusted', async () => {
        const gateway = new StubGateway(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        await KEY_STORES.certificateStore.save(new CertificationPath(nodeCertificate, []), nodeCertificateIssuerPrivateAddress);
        const verifier = await gateway.getGSCVerifier(nodeCertificateIssuerPrivateAddress, StubVerifier);
        const trustedCertificates = verifier.getTrustedCertificates();
        expect(trustedCertificates).toHaveLength(1);
        expect(nodeCertificate.isEqual(trustedCertificates[0])).toBeTrue();
    });
});
class StubGateway extends Gateway {
}
//# sourceMappingURL=Gateway.spec.js.map