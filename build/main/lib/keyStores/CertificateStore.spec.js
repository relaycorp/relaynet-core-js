"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const date_fns_1 = require("date-fns");
const _test_utils_1 = require("../_test_utils");
const keys_1 = require("../crypto_wrappers/keys");
const CertificationPath_1 = require("../pki/CertificationPath");
const issuance_1 = require("../pki/issuance");
const testMocks_1 = require("./testMocks");
const store = new testMocks_1.MockCertificateStore();
beforeEach(() => {
    store.clear();
});
let issuerPrivateAddress;
let issuerCertificate;
let subjectKeyPair;
let subjectPrivateAddress;
let subjectCertificate;
let certificationPath;
beforeAll(async () => {
    const issuerKeyPair = await (0, keys_1.generateRSAKeyPair)();
    issuerPrivateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(issuerKeyPair.publicKey);
    issuerCertificate = await (0, issuance_1.issueGatewayCertificate)({
        subjectPublicKey: issuerKeyPair.publicKey,
        issuerPrivateKey: issuerKeyPair.privateKey,
        validityEndDate: (0, date_fns_1.addSeconds)(new Date(), 10),
    });
    subjectKeyPair = await (0, keys_1.generateRSAKeyPair)();
    subjectPrivateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(subjectKeyPair.publicKey);
    subjectCertificate = await (0, issuance_1.issueGatewayCertificate)({
        issuerCertificate,
        issuerPrivateKey: issuerKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
        validityEndDate: issuerCertificate.expiryDate,
    });
    certificationPath = new CertificationPath_1.CertificationPath(subjectCertificate, [issuerCertificate]);
});
describe('save', () => {
    test('Expired certificate should not be saved', async () => {
        const certificate = await generateSubjectCertificate((0, date_fns_1.subSeconds)(new Date(), 1));
        await store.save(new CertificationPath_1.CertificationPath(certificate, [issuerCertificate]), subjectPrivateAddress);
        expect(store.dataByPrivateAddress).toBeEmpty();
    });
    test('Certification path should be stored', async () => {
        await store.save(certificationPath, issuerPrivateAddress);
        expect(store.dataByPrivateAddress).toHaveProperty(subjectPrivateAddress);
        const serialization = store.dataByPrivateAddress[subjectPrivateAddress][0].serialization;
        (0, _test_utils_1.expectArrayBuffersToEqual)(certificationPath.serialize(), serialization);
    });
    test('Expiry date should be taken from certificate', async () => {
        await store.save(certificationPath, issuerPrivateAddress);
        expect(store.dataByPrivateAddress).toHaveProperty(subjectPrivateAddress);
        expect(store.dataByPrivateAddress[subjectPrivateAddress][0].expiryDate).toEqual((0, date_fns_1.setMilliseconds)(subjectCertificate.expiryDate, 0));
    });
    test('Specified issuer private address should be honoured', async () => {
        const differentIssuerPrivateAddress = `not-${subjectPrivateAddress}`;
        await store.save(certificationPath, differentIssuerPrivateAddress);
        expect(store.dataByPrivateAddress).toHaveProperty(subjectPrivateAddress);
        expect(store.dataByPrivateAddress[subjectPrivateAddress][0].issuerPrivateAddress).toEqual(differentIssuerPrivateAddress);
    });
});
describe('retrieveLatest', () => {
    test('Nothing should be returned if certificate does not exist', async () => {
        await expect(store.retrieveLatest(subjectPrivateAddress, issuerPrivateAddress)).resolves.toBeNull();
    });
    test('Expired certificate should be ignored', async () => {
        const expiredCertificate = await generateSubjectCertificate((0, date_fns_1.subSeconds)(new Date(), 1));
        await store.forceSave(new CertificationPath_1.CertificationPath(expiredCertificate, [issuerCertificate]), issuerPrivateAddress);
        await expect(store.retrieveLatest(subjectPrivateAddress, issuerPrivateAddress)).resolves.toBeNull();
    });
    test('Certificates from another issuer should be ignored', async () => {
        await store.save(certificationPath, `not-${issuerPrivateAddress}`);
        await expect(store.retrieveLatest(subjectPrivateAddress, issuerPrivateAddress)).resolves.toBeNull();
    });
    test('Latest path should be returned', async () => {
        const now = new Date();
        const olderCertificate = await generateSubjectCertificate((0, date_fns_1.addSeconds)(now, 5));
        await store.save(new CertificationPath_1.CertificationPath(olderCertificate, [issuerCertificate]), issuerPrivateAddress);
        const newerCertificate = await generateSubjectCertificate((0, date_fns_1.addSeconds)(now, 10));
        await store.save(new CertificationPath_1.CertificationPath(newerCertificate, [issuerCertificate]), issuerPrivateAddress);
        const path = await store.retrieveLatest(subjectPrivateAddress, issuerPrivateAddress);
        expect(path.leafCertificate.isEqual(newerCertificate)).toBeTrue();
        expect(path.certificateAuthorities).toHaveLength(1);
        expect(path.certificateAuthorities[0].isEqual(issuerCertificate)).toBeTrue();
    });
});
describe('retrieveAll', () => {
    test('Nothing should be returned if no certificate exists', async () => {
        await expect(store.retrieveAll(subjectPrivateAddress, issuerPrivateAddress)).resolves.toBeEmpty();
    });
    test('Expired certificates should be ignored', async () => {
        const validCertificate = await generateSubjectCertificate((0, date_fns_1.addSeconds)(new Date(), 3));
        await store.save(new CertificationPath_1.CertificationPath(validCertificate, [issuerCertificate]), issuerPrivateAddress);
        const expiredCertificate = await generateSubjectCertificate((0, date_fns_1.subSeconds)(new Date(), 1));
        await store.forceSave(new CertificationPath_1.CertificationPath(expiredCertificate, [issuerCertificate]), issuerPrivateAddress);
        const allPaths = await store.retrieveAll(subjectPrivateAddress, issuerPrivateAddress);
        expect(allPaths).toHaveLength(1);
        expect(validCertificate.isEqual(allPaths[0].leafCertificate)).toBeTrue();
    });
    test('All valid certificates should be returned', async () => {
        const certificate1 = await generateSubjectCertificate((0, date_fns_1.addSeconds)(new Date(), 3));
        await store.save(new CertificationPath_1.CertificationPath(certificate1, [issuerCertificate]), issuerPrivateAddress);
        const certificate2 = await generateSubjectCertificate((0, date_fns_1.addSeconds)(new Date(), 5));
        await store.save(new CertificationPath_1.CertificationPath(certificate2, [issuerCertificate]), issuerPrivateAddress);
        const allCertificates = await store.retrieveAll(subjectPrivateAddress, issuerPrivateAddress);
        expect(allCertificates).toHaveLength(2);
        expect(allCertificates.filter((p) => certificate1.isEqual(p.leafCertificate))).toHaveLength(1);
        expect(allCertificates.filter((p) => certificate2.isEqual(p.leafCertificate))).toHaveLength(1);
        expect(allCertificates[0].certificateAuthorities).toHaveLength(1);
        expect(allCertificates[0].certificateAuthorities[0].isEqual(issuerCertificate)).toBeTrue();
        expect(allCertificates[1].certificateAuthorities).toHaveLength(1);
        expect(allCertificates[1].certificateAuthorities[0].isEqual(issuerCertificate)).toBeTrue();
    });
    test('Certificates from another issuer should be ignored', async () => {
        const certificate = await generateSubjectCertificate((0, date_fns_1.addSeconds)(new Date(), 3));
        await store.save(new CertificationPath_1.CertificationPath(certificate, []), `not-${issuerPrivateAddress}`);
        await expect(store.retrieveAll(subjectPrivateAddress, issuerPrivateAddress)).resolves.toBeEmpty();
    });
});
describe('deleteExpired', () => {
    test('Method should be exposed', async () => {
        await expect(store.deleteExpired()).rejects.toThrowWithMessage(Error, 'Not implemented');
    });
});
async function generateSubjectCertificate(validityEndDate) {
    return (0, issuance_1.issueGatewayCertificate)({
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
        validityEndDate,
        validityStartDate: (0, date_fns_1.subSeconds)(validityEndDate, 1),
    });
}
//# sourceMappingURL=CertificateStore.spec.js.map