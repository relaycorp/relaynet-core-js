"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const date_fns_1 = require("date-fns");
const _test_utils_1 = require("../_test_utils");
const envelopedData_1 = require("../crypto_wrappers/cms/envelopedData");
const keys_1 = require("../crypto_wrappers/keys");
const testMocks_1 = require("../keyStores/testMocks");
const signatures_1 = require("../messages/bindings/signatures");
const CertificationPath_1 = require("../pki/CertificationPath");
const issuance_1 = require("../pki/issuance");
const _test_utils_2 = require("../ramf/_test_utils");
const _test_utils_3 = require("./_test_utils");
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
describe('getIdentityPublicKey', () => {
    test('Public key should be returned', async () => {
        const node = new _test_utils_3.StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        await expect((0, keys_1.derSerializePublicKey)(await node.getIdentityPublicKey())).resolves.toEqual(await (0, keys_1.derSerializePublicKey)(nodePrivateKey));
    });
});
describe('getGSCSigner', () => {
    test('Nothing should be returned if certificate does not exist', async () => {
        const node = new _test_utils_3.StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        await expect(node.getGSCSigner(nodeCertificateIssuerPrivateAddress, signatures_1.ParcelDeliverySigner)).resolves.toBeNull();
    });
    test('Signer should be of the type requested if certificate exists', async () => {
        const node = new _test_utils_3.StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        await KEY_STORES.certificateStore.save(new CertificationPath_1.CertificationPath(nodeCertificate, []), nodeCertificateIssuerPrivateAddress);
        const signer = await node.getGSCSigner(nodeCertificateIssuerPrivateAddress, signatures_1.ParcelDeliverySigner);
        expect(signer).toBeInstanceOf(signatures_1.ParcelDeliverySigner);
    });
    test('Signer should receive the certificate and private key of the node', async () => {
        const node = new _test_utils_3.StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        await KEY_STORES.certificateStore.save(new CertificationPath_1.CertificationPath(nodeCertificate, []), nodeCertificateIssuerPrivateAddress);
        const signer = await node.getGSCSigner(nodeCertificateIssuerPrivateAddress, signatures_1.ParcelDeliverySigner);
        const plaintext = (0, _test_utils_1.arrayBufferFrom)('hiya');
        const verifier = new signatures_1.ParcelDeliveryVerifier([nodeCertificateIssuer]);
        const signature = await signer.sign(plaintext);
        await verifier.verify(signature, plaintext);
    });
});
describe('generateSessionKey', () => {
    const PRIVATE_ADDRESS = '0deadbeef';
    test('Key should not be bound to any peer by default', async () => {
        const node = new _test_utils_3.StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        const sessionKey = await node.generateSessionKey();
        await expect((0, keys_1.derSerializePublicKey)(await KEY_STORES.privateKeyStore.retrieveUnboundSessionKey(sessionKey.keyId, node.privateAddress))).resolves.toEqual(await (0, keys_1.derSerializePublicKey)(sessionKey.publicKey));
    });
    test('Key should be bound to a peer if explicitly set', async () => {
        const node = new _test_utils_3.StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        const peerPrivateAddress = `${PRIVATE_ADDRESS}cousin`;
        const sessionKey = await node.generateSessionKey(peerPrivateAddress);
        await expect((0, keys_1.derSerializePublicKey)(await KEY_STORES.privateKeyStore.retrieveSessionKey(sessionKey.keyId, node.privateAddress, peerPrivateAddress))).resolves.toEqual(await (0, keys_1.derSerializePublicKey)(sessionKey.publicKey));
    });
});
describe('unwrapMessagePayload', () => {
    const PAYLOAD_PLAINTEXT_CONTENT = (0, _test_utils_1.arrayBufferFrom)('payload content');
    const RECIPIENT_ADDRESS = 'https://example.com';
    let peerCertificate;
    beforeAll(async () => {
        const peerKeyPair = await (0, keys_1.generateRSAKeyPair)();
        peerCertificate = await (0, issuance_1.issueGatewayCertificate)({
            issuerPrivateKey: peerKeyPair.privateKey,
            subjectPublicKey: peerKeyPair.publicKey,
            validityEndDate: (0, date_fns_1.addDays)(new Date(), 1),
        });
    });
    test('Payload plaintext should be returned', async () => {
        const node = new _test_utils_3.StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        const sessionKey = await node.generateSessionKey();
        const { envelopedData } = await envelopedData_1.SessionEnvelopedData.encrypt(PAYLOAD_PLAINTEXT_CONTENT, sessionKey);
        const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, peerCertificate, Buffer.from(envelopedData.serialize()));
        const payloadPlaintext = await node.unwrapMessagePayload(message);
        (0, _test_utils_1.expectArrayBuffersToEqual)(payloadPlaintext.content, PAYLOAD_PLAINTEXT_CONTENT);
    });
    test('Originator session key should be stored', async () => {
        const node = new _test_utils_3.StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        const sessionKey = await node.generateSessionKey();
        const { envelopedData, dhKeyId } = await envelopedData_1.SessionEnvelopedData.encrypt(PAYLOAD_PLAINTEXT_CONTENT, sessionKey);
        const message = new _test_utils_2.StubMessage(RECIPIENT_ADDRESS, peerCertificate, Buffer.from(envelopedData.serialize()));
        await node.unwrapMessagePayload(message);
        const storedKey = KEY_STORES.publicKeyStore.sessionKeys[await peerCertificate.calculateSubjectPrivateAddress()];
        expect(storedKey.publicKeyCreationTime).toEqual(message.creationDate);
        expect(storedKey.publicKeyId).toEqual(Buffer.from(dhKeyId));
        expect(storedKey.publicKeyDer).toEqual(await (0, keys_1.derSerializePublicKey)((await envelopedData.getOriginatorKey()).publicKey));
    });
});
//# sourceMappingURL=Node.spec.js.map