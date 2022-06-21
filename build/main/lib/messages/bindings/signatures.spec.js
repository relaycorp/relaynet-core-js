"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const _test_utils_1 = require("../../_test_utils");
const keys_1 = require("../../crypto_wrappers/keys");
const oids_1 = require("../../oids");
const signatures_1 = require("./signatures");
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
describe('Parcel collection', () => {
    test('Signer should use correct OID', () => {
        const signer = new signatures_1.ParcelCollectionHandshakeSigner(signerCertificate, signerPrivateKey);
        expect(signer.oid).toEqual(oids_1.RELAYNET_OIDS.SIGNATURE.PARCEL_COLLECTION_HANDSHAKE);
    });
    test('Verifier should use correct OID', () => {
        const verifier = new signatures_1.ParcelCollectionHandshakeVerifier([caCertificate]);
        expect(verifier.oid).toEqual(oids_1.RELAYNET_OIDS.SIGNATURE.PARCEL_COLLECTION_HANDSHAKE);
    });
});
describe('Parcel delivery', () => {
    test('Signer should use correct OID', () => {
        const signer = new signatures_1.ParcelDeliverySigner(signerCertificate, signerPrivateKey);
        expect(signer.oid).toEqual(oids_1.RELAYNET_OIDS.SIGNATURE.PARCEL_DELIVERY);
    });
    test('Verifier should use correct OID', () => {
        const verifier = new signatures_1.ParcelDeliveryVerifier([caCertificate]);
        expect(verifier.oid).toEqual(oids_1.RELAYNET_OIDS.SIGNATURE.PARCEL_DELIVERY);
    });
});
//# sourceMappingURL=signatures.spec.js.map