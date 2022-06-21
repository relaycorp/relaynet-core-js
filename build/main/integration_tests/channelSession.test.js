"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const pkijs = __importStar(require("pkijs"));
const __1 = require("..");
const _utils_1 = require("../lib/crypto_wrappers/cms/_utils");
const _test_utils_1 = require("../lib/_test_utils");
test('Encryption and decryption with subsequent DH keys', async () => {
    const bobKeyPair1 = await (0, __1.generateECDHKeyPair)();
    const bobKeyPair1Id = Buffer.from('bob key pair 1');
    // Run 1: Alice initiates contact with Bob. Bob decrypts message.
    const plaintext1 = (0, _test_utils_1.arrayBufferFrom)('Hi. My name is Alice.');
    const encryptionResult1 = await __1.SessionEnvelopedData.encrypt(plaintext1, {
        keyId: bobKeyPair1Id,
        publicKey: bobKeyPair1.publicKey,
    });
    const decryptedPlaintext1 = await encryptionResult1.envelopedData.decrypt(bobKeyPair1.privateKey);
    (0, _test_utils_1.expectArrayBuffersToEqual)(decryptedPlaintext1, plaintext1);
    checkRecipientInfo(encryptionResult1.envelopedData, bobKeyPair1Id);
    // Run 2: Bob replies to Alice. They have one DH key pair each.
    const plaintext2 = (0, _test_utils_1.arrayBufferFrom)('Hi, Alice. My name is Bob.');
    const alicePublicKey1 = await encryptionResult1.envelopedData.getOriginatorKey();
    const encryptionResult2 = await __1.SessionEnvelopedData.encrypt(plaintext2, alicePublicKey1);
    const decryptedPlaintext2 = await encryptionResult2.envelopedData.decrypt(encryptionResult1.dhPrivateKey);
    (0, _test_utils_1.expectArrayBuffersToEqual)(decryptedPlaintext2, plaintext2);
    checkRecipientInfo(encryptionResult2.envelopedData, alicePublicKey1.keyId);
    // Run 3: Alice replies to Bob. Alice has two DH key pairs and Bob just one.
    const plaintext3 = (0, _test_utils_1.arrayBufferFrom)('Nice to meet you, Bob.');
    const bobPublicKey2 = await encryptionResult2.envelopedData.getOriginatorKey();
    const encryptionResult3 = await __1.SessionEnvelopedData.encrypt(plaintext3, bobPublicKey2);
    const decryptedPlaintext3 = await encryptionResult3.envelopedData.decrypt(encryptionResult2.dhPrivateKey);
    (0, _test_utils_1.expectArrayBuffersToEqual)(decryptedPlaintext3, plaintext3);
    checkRecipientInfo(encryptionResult3.envelopedData, bobPublicKey2.keyId);
});
test('EnvelopedData should be decrypted after serialization', async () => {
    // Make sure data can be decrypted after the EnvelopedData and/or the certificate have
    // been serialized. This is a regression test for
    // https://github.com/PeculiarVentures/PKI.js/pull/258
    const dhKeyPair = await (0, __1.generateECDHKeyPair)();
    const keyId = Buffer.from('key id');
    const plaintext = (0, _test_utils_1.arrayBufferFrom)('plaintext');
    const { envelopedData } = await __1.SessionEnvelopedData.encrypt(plaintext, {
        keyId,
        publicKey: dhKeyPair.publicKey,
    });
    // Check it can be decrypted before serializing it:
    (0, _test_utils_1.expectArrayBuffersToEqual)(await envelopedData.decrypt(dhKeyPair.privateKey), plaintext);
    // Check it can be decrypted after serializing and deserializing it:
    const envelopedDataDeserialized = __1.EnvelopedData.deserialize(envelopedData.serialize());
    (0, _test_utils_1.expectArrayBuffersToEqual)(await envelopedDataDeserialized.decrypt(dhKeyPair.privateKey), plaintext);
});
function checkRecipientInfo(envelopedData, expectedRecipientSessionKeyId) {
    expect(envelopedData.pkijsEnvelopedData.recipientInfos).toHaveLength(1);
    const recipientInfo = envelopedData.pkijsEnvelopedData.recipientInfos[0];
    // RecipientInfo MUST use the KeyAgreeRecipientInfo choice
    expect(recipientInfo).toHaveProperty('variant', 2);
    // KeyAgreeRecipientInfo MUST use the OriginatorPublicKey choice
    expect(recipientInfo).toHaveProperty('value.originator.variant', 3);
    // Validate keyEncryptionAlgorithm
    (0, _utils_1.assertPkiType)(recipientInfo.value, pkijs.KeyAgreeRecipientInfo, 'recipientInfo.value');
    expect(recipientInfo.value.keyEncryptionAlgorithm).toHaveProperty('algorithmId', '1.3.132.1.11.3');
    const keyEncryptionAlgorithmParams = new pkijs.AlgorithmIdentifier({
        schema: recipientInfo.value.keyEncryptionAlgorithm.algorithmParams,
    });
    expect(keyEncryptionAlgorithmParams).toHaveProperty('algorithmId', '2.16.840.1.101.3.4.1.45');
    // Validate recipientEncryptedKeys
    expect(envelopedData.getRecipientKeyId()).toEqual(expectedRecipientSessionKeyId);
}
//# sourceMappingURL=channelSession.test.js.map