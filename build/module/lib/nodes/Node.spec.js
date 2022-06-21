import { addDays, setMilliseconds } from 'date-fns';
import { arrayBufferFrom, expectArrayBuffersToEqual, reSerializeCertificate } from '../_test_utils';
import { SessionEnvelopedData } from '../crypto_wrappers/cms/envelopedData';
import { derSerializePublicKey, generateRSAKeyPair, getPrivateAddressFromIdentityKey, } from '../crypto_wrappers/keys';
import { MockKeyStoreSet } from '../keyStores/testMocks';
import { ParcelDeliverySigner, ParcelDeliveryVerifier } from '../messages/bindings/signatures';
import { CertificationPath } from '../pki/CertificationPath';
import { issueGatewayCertificate } from '../pki/issuance';
import { StubMessage } from '../ramf/_test_utils';
import { StubNode } from './_test_utils';
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
describe('getIdentityPublicKey', () => {
    test('Public key should be returned', async () => {
        const node = new StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        await expect(derSerializePublicKey(await node.getIdentityPublicKey())).resolves.toEqual(await derSerializePublicKey(nodePrivateKey));
    });
});
describe('getGSCSigner', () => {
    test('Nothing should be returned if certificate does not exist', async () => {
        const node = new StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        await expect(node.getGSCSigner(nodeCertificateIssuerPrivateAddress, ParcelDeliverySigner)).resolves.toBeNull();
    });
    test('Signer should be of the type requested if certificate exists', async () => {
        const node = new StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        await KEY_STORES.certificateStore.save(new CertificationPath(nodeCertificate, []), nodeCertificateIssuerPrivateAddress);
        const signer = await node.getGSCSigner(nodeCertificateIssuerPrivateAddress, ParcelDeliverySigner);
        expect(signer).toBeInstanceOf(ParcelDeliverySigner);
    });
    test('Signer should receive the certificate and private key of the node', async () => {
        const node = new StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        await KEY_STORES.certificateStore.save(new CertificationPath(nodeCertificate, []), nodeCertificateIssuerPrivateAddress);
        const signer = await node.getGSCSigner(nodeCertificateIssuerPrivateAddress, ParcelDeliverySigner);
        const plaintext = arrayBufferFrom('hiya');
        const verifier = new ParcelDeliveryVerifier([nodeCertificateIssuer]);
        const signature = await signer.sign(plaintext);
        await verifier.verify(signature, plaintext);
    });
});
describe('generateSessionKey', () => {
    const PRIVATE_ADDRESS = '0deadbeef';
    test('Key should not be bound to any peer by default', async () => {
        const node = new StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        const sessionKey = await node.generateSessionKey();
        await expect(derSerializePublicKey(await KEY_STORES.privateKeyStore.retrieveUnboundSessionKey(sessionKey.keyId, node.privateAddress))).resolves.toEqual(await derSerializePublicKey(sessionKey.publicKey));
    });
    test('Key should be bound to a peer if explicitly set', async () => {
        const node = new StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        const peerPrivateAddress = `${PRIVATE_ADDRESS}cousin`;
        const sessionKey = await node.generateSessionKey(peerPrivateAddress);
        await expect(derSerializePublicKey(await KEY_STORES.privateKeyStore.retrieveSessionKey(sessionKey.keyId, node.privateAddress, peerPrivateAddress))).resolves.toEqual(await derSerializePublicKey(sessionKey.publicKey));
    });
});
describe('unwrapMessagePayload', () => {
    const PAYLOAD_PLAINTEXT_CONTENT = arrayBufferFrom('payload content');
    const RECIPIENT_ADDRESS = 'https://example.com';
    let peerCertificate;
    beforeAll(async () => {
        const peerKeyPair = await generateRSAKeyPair();
        peerCertificate = await issueGatewayCertificate({
            issuerPrivateKey: peerKeyPair.privateKey,
            subjectPublicKey: peerKeyPair.publicKey,
            validityEndDate: addDays(new Date(), 1),
        });
    });
    test('Payload plaintext should be returned', async () => {
        const node = new StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        const sessionKey = await node.generateSessionKey();
        const { envelopedData } = await SessionEnvelopedData.encrypt(PAYLOAD_PLAINTEXT_CONTENT, sessionKey);
        const message = new StubMessage(RECIPIENT_ADDRESS, peerCertificate, Buffer.from(envelopedData.serialize()));
        const payloadPlaintext = await node.unwrapMessagePayload(message);
        expectArrayBuffersToEqual(payloadPlaintext.content, PAYLOAD_PLAINTEXT_CONTENT);
    });
    test('Originator session key should be stored', async () => {
        const node = new StubNode(nodePrivateAddress, nodePrivateKey, KEY_STORES, {});
        const sessionKey = await node.generateSessionKey();
        const { envelopedData, dhKeyId } = await SessionEnvelopedData.encrypt(PAYLOAD_PLAINTEXT_CONTENT, sessionKey);
        const message = new StubMessage(RECIPIENT_ADDRESS, peerCertificate, Buffer.from(envelopedData.serialize()));
        await node.unwrapMessagePayload(message);
        const storedKey = KEY_STORES.publicKeyStore.sessionKeys[await peerCertificate.calculateSubjectPrivateAddress()];
        expect(storedKey.publicKeyCreationTime).toEqual(message.creationDate);
        expect(storedKey.publicKeyId).toEqual(Buffer.from(dhKeyId));
        expect(storedKey.publicKeyDer).toEqual(await derSerializePublicKey((await envelopedData.getOriginatorKey()).publicKey));
    });
});
//# sourceMappingURL=Node.spec.js.map