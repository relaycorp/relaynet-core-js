"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const asn1js_1 = require("asn1js");
const _test_utils_1 = require("../../_test_utils");
const asn1_1 = require("../../asn1");
const signedData_1 = require("../../crypto_wrappers/cms/signedData");
const keys_1 = require("../../crypto_wrappers/keys");
const _test_utils_2 = require("./_test_utils");
let signerPrivateKey;
let signerCertificate;
let caCertificate;
beforeAll(async () => {
    const caKeyPair = await (0, keys_1.generateRSAKeyPair)();
    caCertificate = await (0, _test_utils_1.generateStubCert)({
        attributes: { isCA: true },
        issuerPrivateKey: caKeyPair.privateKey,
        subjectPublicKey: caKeyPair.publicKey,
    });
    const signerKeyPair = await (0, keys_1.generateRSAKeyPair)();
    signerPrivateKey = signerKeyPair.privateKey;
    signerCertificate = await (0, _test_utils_1.generateStubCert)({
        issuerCertificate: caCertificate,
        issuerPrivateKey: caKeyPair.privateKey,
        subjectPublicKey: signerKeyPair.publicKey,
    });
});
const PLAINTEXT = (0, _test_utils_1.arrayBufferFrom)('the plaintext');
test('Signer certificate should be exposed', () => {
    const signer = new _test_utils_2.StubSigner(signerCertificate, signerPrivateKey);
    expect(signer.certificate).toEqual(signerCertificate);
});
describe('sign', () => {
    const OID = new asn1js_1.ObjectIdentifier({ value: _test_utils_2.STUB_OID_VALUE });
    test('Plaintext should not be encapsulated', async () => {
        const signer = new _test_utils_2.StubSigner(signerCertificate, signerPrivateKey);
        const signedDataSerialized = await signer.sign(PLAINTEXT);
        const signedData = signedData_1.SignedData.deserialize(signedDataSerialized);
        expect(signedData.plaintext).toBeNull();
    });
    test('Certificate should be encapsulated', async () => {
        const signer = new _test_utils_2.StubSigner(signerCertificate, signerPrivateKey);
        const signedDataSerialized = await signer.sign(PLAINTEXT);
        const signedData = signedData_1.SignedData.deserialize(signedDataSerialized);
        expect(signedData.signerCertificate).not.toBeNull();
    });
    test('Signature should validate', async () => {
        const signer = new _test_utils_2.StubSigner(signerCertificate, signerPrivateKey);
        const signedDataSerialized = await signer.sign(PLAINTEXT);
        const signedData = signedData_1.SignedData.deserialize(signedDataSerialized);
        const expectedPlaintext = (0, asn1_1.makeImplicitlyTaggedSequence)(OID, new asn1js_1.OctetString({ valueHex: PLAINTEXT })).toBER();
        await signedData.verify(expectedPlaintext);
    });
});
//# sourceMappingURL=Signer.spec.js.map