"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const __1 = require("..");
const _test_utils_1 = require("../lib/_test_utils");
const ONE_SECOND_AGO = new Date();
ONE_SECOND_AGO.setSeconds(ONE_SECOND_AGO.getSeconds() - 1, 0);
const TOMORROW = new Date();
TOMORROW.setDate(TOMORROW.getDate() + 1);
let publicGatewayCert;
let privateGatewayCert;
let peerEndpointCert;
let endpointPdaCert;
beforeAll(async () => {
    const publicGatewayKeyPair = await (0, __1.generateRSAKeyPair)();
    publicGatewayCert = (0, _test_utils_1.reSerializeCertificate)(await (0, __1.issueGatewayCertificate)({
        issuerPrivateKey: publicGatewayKeyPair.privateKey,
        subjectPublicKey: publicGatewayKeyPair.publicKey,
        validityEndDate: TOMORROW,
        validityStartDate: ONE_SECOND_AGO,
    }));
    const localGatewayKeyPair = await (0, __1.generateRSAKeyPair)();
    privateGatewayCert = (0, _test_utils_1.reSerializeCertificate)(await (0, __1.issueGatewayCertificate)({
        issuerCertificate: publicGatewayCert,
        issuerPrivateKey: publicGatewayKeyPair.privateKey,
        subjectPublicKey: localGatewayKeyPair.publicKey,
        validityEndDate: TOMORROW,
        validityStartDate: ONE_SECOND_AGO,
    }));
    const peerEndpointKeyPair = await (0, __1.generateRSAKeyPair)();
    peerEndpointCert = (0, _test_utils_1.reSerializeCertificate)(await (0, __1.issueEndpointCertificate)({
        issuerCertificate: privateGatewayCert,
        issuerPrivateKey: localGatewayKeyPair.privateKey,
        subjectPublicKey: peerEndpointKeyPair.publicKey,
        validityEndDate: TOMORROW,
        validityStartDate: ONE_SECOND_AGO,
    }));
    const endpointKeyPair = await (0, __1.generateRSAKeyPair)();
    endpointPdaCert = (0, _test_utils_1.reSerializeCertificate)(await (0, __1.issueDeliveryAuthorization)({
        issuerCertificate: peerEndpointCert,
        issuerPrivateKey: peerEndpointKeyPair.privateKey,
        subjectPublicKey: endpointKeyPair.publicKey,
        validityEndDate: TOMORROW,
        validityStartDate: ONE_SECOND_AGO,
    }));
});
test('Messages by authorized senders should be accepted', async () => {
    const parcel = new __1.Parcel(await peerEndpointCert.calculateSubjectPrivateAddress(), endpointPdaCert, Buffer.from('hey'), {
        creationDate: ONE_SECOND_AGO,
        senderCaCertificateChain: [peerEndpointCert, privateGatewayCert],
    });
    await parcel.validate(undefined, [publicGatewayCert]);
});
test('Certificate chain should be computed corrected', async () => {
    const parcel = new __1.Parcel(await peerEndpointCert.calculateSubjectPrivateAddress(), endpointPdaCert, Buffer.from('hey'), { senderCaCertificateChain: [peerEndpointCert, privateGatewayCert] });
    await expect(parcel.getSenderCertificationPath([publicGatewayCert])).resolves.toEqual([
        expect.toSatisfy((c) => c.isEqual(endpointPdaCert)),
        expect.toSatisfy((c) => c.isEqual(peerEndpointCert)),
        expect.toSatisfy((c) => c.isEqual(privateGatewayCert)),
        expect.toSatisfy((c) => c.isEqual(publicGatewayCert)),
    ]);
});
test('Messages by unauthorized senders should be refused', async () => {
    const keyPair = await (0, __1.generateRSAKeyPair)();
    const unauthorizedSenderCertificate = (0, _test_utils_1.reSerializeCertificate)(await (0, __1.issueEndpointCertificate)({
        issuerPrivateKey: keyPair.privateKey,
        subjectPublicKey: keyPair.publicKey,
        validityEndDate: TOMORROW,
        validityStartDate: ONE_SECOND_AGO,
    }));
    const parcel = new __1.Parcel(await peerEndpointCert.calculateSubjectPrivateAddress(), unauthorizedSenderCertificate, Buffer.from('hey'), {
        creationDate: ONE_SECOND_AGO,
        senderCaCertificateChain: [peerEndpointCert, privateGatewayCert],
    });
    await expect(parcel.validate(undefined, [publicGatewayCert])).rejects.toHaveProperty('message', 'Sender is not authorized: No valid certificate paths found');
});
//# sourceMappingURL=pki.test.js.map