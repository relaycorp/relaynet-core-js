"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const date_fns_1 = require("date-fns");
const _test_utils_1 = require("../../_test_utils");
const envelopedData_1 = require("../../crypto_wrappers/cms/envelopedData");
const keys_1 = require("../../crypto_wrappers/keys");
const testMocks_1 = require("../../keyStores/testMocks");
const issuance_1 = require("../../pki/issuance");
const _test_utils_2 = require("../../ramf/_test_utils");
const errors_1 = require("../errors");
const Channel_1 = require("./Channel");
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
beforeEach(() => {
    KEY_STORES.clear();
});
const PAYLOAD_PLAINTEXT_CONTENT = (0, _test_utils_1.arrayBufferFrom)('payload content');
describe('wrapMessagePayload', () => {
    const stubPayload = new _test_utils_2.StubPayload(PAYLOAD_PLAINTEXT_CONTENT);
    let peerSessionKey;
    let peerSessionPrivateKey;
    beforeEach(async () => {
        const recipientSessionKeyPair = await (0, keys_1.generateECDHKeyPair)();
        peerSessionPrivateKey = recipientSessionKeyPair.privateKey;
        peerSessionKey = {
            keyId: Buffer.from('key id'),
            publicKey: recipientSessionKeyPair.publicKey,
        };
        await KEY_STORES.publicKeyStore.saveSessionKey(peerSessionKey, peerPrivateAddress, new Date());
    });
    test('There should be a session key for the recipient', async () => {
        const unknownPeerPrivateAddress = `not-${peerPrivateAddress}`;
        const channel = new StubChannel(nodePrivateKey, nodeCertificate, unknownPeerPrivateAddress, peerPublicKey, KEY_STORES);
        await expect(channel.wrapMessagePayload(stubPayload)).rejects.toThrowWithMessage(errors_1.NodeError, `Could not find session key for peer ${unknownPeerPrivateAddress}`);
    });
    test('Payload should be encrypted with the session key of the recipient', async () => {
        const channel = new StubChannel(nodePrivateKey, nodeCertificate, peerPrivateAddress, peerPublicKey, KEY_STORES);
        const payloadSerialized = await channel.wrapMessagePayload(stubPayload);
        const payloadEnvelopedData = await envelopedData_1.SessionEnvelopedData.deserialize(payloadSerialized);
        expect(payloadEnvelopedData.getRecipientKeyId()).toEqual(peerSessionKey.keyId);
        await expect(payloadEnvelopedData.decrypt(peerSessionPrivateKey)).resolves.toEqual(stubPayload.serialize());
    });
    test('Passing the payload as an ArrayBuffer should be supported', async () => {
        const payloadPlaintext = stubPayload.serialize();
        const channel = new StubChannel(nodePrivateKey, nodeCertificate, peerPrivateAddress, peerPublicKey, KEY_STORES);
        const payloadSerialized = await channel.wrapMessagePayload(stubPayload);
        const payloadEnvelopedData = await envelopedData_1.SessionEnvelopedData.deserialize(payloadSerialized);
        await expect(payloadEnvelopedData.decrypt(peerSessionPrivateKey)).resolves.toEqual(payloadPlaintext);
    });
    test('The new ephemeral session key of the sender should be stored', async () => {
        const channel = new StubChannel(nodePrivateKey, nodeCertificate, peerPrivateAddress, peerPublicKey, KEY_STORES);
        const payloadSerialized = await channel.wrapMessagePayload(stubPayload);
        const payloadEnvelopedData = (await envelopedData_1.SessionEnvelopedData.deserialize(payloadSerialized));
        const originatorSessionKey = await payloadEnvelopedData.getOriginatorKey();
        await expect(KEY_STORES.privateKeyStore.retrieveSessionKey(originatorSessionKey.keyId, await nodeCertificate.calculateSubjectPrivateAddress(), peerPrivateAddress)).resolves.toBeTruthy();
    });
    test('Encryption options should be honoured if set', async () => {
        const aesKeySize = 192;
        const channel = new StubChannel(nodePrivateKey, nodeCertificate, peerPrivateAddress, peerPublicKey, KEY_STORES, { encryption: { aesKeySize } });
        const payloadSerialized = await channel.wrapMessagePayload(stubPayload);
        const payloadEnvelopedData = await envelopedData_1.SessionEnvelopedData.deserialize(payloadSerialized);
        const encryptedContentInfo = payloadEnvelopedData.pkijsEnvelopedData.encryptedContentInfo;
        expect(encryptedContentInfo.contentEncryptionAlgorithm.algorithmId).toEqual(_test_utils_1.CRYPTO_OIDS.AES_CBC_192);
    });
});
class StubChannel extends Channel_1.Channel {
    getOutboundRAMFAddress() {
        throw new Error('not implemented');
    }
}
//# sourceMappingURL=Channel.spec.js.map