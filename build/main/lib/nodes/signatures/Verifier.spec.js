"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const _test_utils_1 = require("../../_test_utils");
const CMSError_1 = __importDefault(require("../../crypto_wrappers/cms/CMSError"));
const keys_1 = require("../../crypto_wrappers/keys");
const CertificateError_1 = __importDefault(require("../../crypto_wrappers/x509/CertificateError"));
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
describe('verify', () => {
    test('Malformed signatures should be refused', async () => {
        const signedDataSerialized = (0, _test_utils_1.arrayBufferFrom)('not valid');
        const verifier = new _test_utils_2.StubVerifier([caCertificate]);
        await expect(verifier.verify(signedDataSerialized, PLAINTEXT)).rejects.toBeInstanceOf(CMSError_1.default);
    });
    test('Invalid signatures should be refused', async () => {
        const differentKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const illegitimateSigner = new _test_utils_2.StubSigner(signerCertificate, differentKeyPair.privateKey);
        const signedDataSerialized = await illegitimateSigner.sign(PLAINTEXT);
        const verifier = new _test_utils_2.StubVerifier([caCertificate]);
        await expect(verifier.verify(signedDataSerialized, PLAINTEXT)).rejects.toBeInstanceOf(CMSError_1.default);
    });
    test('Untrusted signers should be refused', async () => {
        const signer = new _test_utils_2.StubSigner(signerCertificate, signerPrivateKey);
        const signedDataSerialized = await signer.sign(PLAINTEXT);
        const verifier = new _test_utils_2.StubVerifier([]);
        await expect(verifier.verify(signedDataSerialized, PLAINTEXT)).rejects.toBeInstanceOf(CertificateError_1.default);
    });
    test('Signer certificate should be output if trusted and signature is valid', async () => {
        const signer = new _test_utils_2.StubSigner(signerCertificate, signerPrivateKey);
        const signedDataSerialized = await signer.sign(PLAINTEXT);
        const verifier = new _test_utils_2.StubVerifier([caCertificate]);
        const actualSignerCertificate = await verifier.verify(signedDataSerialized, PLAINTEXT);
        await expect(actualSignerCertificate.isEqual(signerCertificate)).toBeTrue();
    });
    test('Signature should verify if issuer of signer is not a root CA', async () => {
        // PKI.js' SignedData.verify() can't be relied on to verify the signer, so we have to do our
        // own verification: https://github.com/relaycorp/relaynet-core-js/issues/178
        const caKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const rootCertificate = await (0, _test_utils_1.generateStubCert)({
            attributes: { isCA: true, pathLenConstraint: 1 },
            issuerPrivateKey: caKeyPair.privateKey,
            subjectPublicKey: caKeyPair.publicKey,
        });
        const intermediateKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const intermediateCertificate = await (0, _test_utils_1.generateStubCert)({
            attributes: { isCA: true, pathLenConstraint: 0 },
            issuerCertificate: rootCertificate,
            issuerPrivateKey: caKeyPair.privateKey,
            subjectPublicKey: intermediateKeyPair.publicKey,
        });
        const nonRootSignerKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const nonRootSignerCertificate = await (0, _test_utils_1.generateStubCert)({
            attributes: { isCA: true, pathLenConstraint: 0 },
            issuerCertificate: intermediateCertificate,
            issuerPrivateKey: intermediateKeyPair.privateKey,
            subjectPublicKey: nonRootSignerKeyPair.publicKey,
        });
        const signer = new _test_utils_2.StubSigner(nonRootSignerCertificate, nonRootSignerKeyPair.privateKey);
        const signedDataSerialized = await signer.sign(PLAINTEXT);
        const verifier = new _test_utils_2.StubVerifier([intermediateCertificate]);
        await verifier.verify(signedDataSerialized, PLAINTEXT);
    });
});
//# sourceMappingURL=Verifier.spec.js.map