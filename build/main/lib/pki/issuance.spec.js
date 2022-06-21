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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const pkijs = __importStar(require("pkijs"));
const _test_utils_1 = require("../_test_utils");
const keys_1 = require("../crypto_wrappers/keys");
const Certificate_1 = __importDefault(require("../crypto_wrappers/x509/Certificate"));
const issuance_1 = require("./issuance");
let stubSubjectKeyPair;
let stubCertificate;
beforeAll(async () => {
    stubSubjectKeyPair = await (0, keys_1.generateRSAKeyPair)();
    stubCertificate = await (0, _test_utils_1.generateStubCert)({
        issuerPrivateKey: stubSubjectKeyPair.privateKey,
        subjectPublicKey: stubSubjectKeyPair.publicKey,
    });
});
const mockCertificateIssue = jest.spyOn(Certificate_1.default, 'issue');
beforeEach(() => {
    mockCertificateIssue.mockReset();
    mockCertificateIssue.mockResolvedValue(Promise.resolve(stubCertificate));
});
afterAll(() => {
    mockCertificateIssue.mockRestore();
});
let basicCertificateOptions;
beforeAll(async () => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    basicCertificateOptions = {
        issuerPrivateKey: stubSubjectKeyPair.privateKey,
        subjectPublicKey: stubSubjectKeyPair.publicKey,
        validityEndDate: tomorrow,
        validityStartDate: new Date(),
    };
});
describe('issueGatewayCertificate', () => {
    let minimalCertificateOptions;
    beforeAll(() => {
        minimalCertificateOptions = {
            issuerPrivateKey: stubSubjectKeyPair.privateKey,
            subjectPublicKey: stubSubjectKeyPair.publicKey,
            validityEndDate: new Date(),
        };
    });
    test('Certificate should be a valid X.509 certificate', async () => {
        const certificate = await (0, issuance_1.issueGatewayCertificate)(minimalCertificateOptions);
        expect(certificate).toBe(stubCertificate);
    });
    test('Certificate should honor all the basic options', async () => {
        await (0, issuance_1.issueGatewayCertificate)({ ...minimalCertificateOptions, ...basicCertificateOptions });
        expect(mockCertificateIssue.mock.calls[0][0]).toMatchObject(basicCertificateOptions);
    });
    test('Certificate should have its private address as its Common Name (CN)', async () => {
        await (0, issuance_1.issueGatewayCertificate)(minimalCertificateOptions);
        expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('commonName', `0${await (0, keys_1.getPublicKeyDigestHex)(stubSubjectKeyPair.publicKey)}`);
    });
    test('Subject should be marked as CA', async () => {
        await (0, issuance_1.issueGatewayCertificate)(minimalCertificateOptions);
        expect(mockCertificateIssue).toBeCalledTimes(1);
        expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('isCA', true);
    });
    test('pathLenConstraint should be 2 if self-issued', async () => {
        await (0, issuance_1.issueGatewayCertificate)(minimalCertificateOptions);
        expect(mockCertificateIssue).toBeCalledTimes(1);
        expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('pathLenConstraint', 2);
    });
    test('pathLenConstraint should be 1 if issued by another gateway', async () => {
        await (0, issuance_1.issueGatewayCertificate)({
            ...minimalCertificateOptions,
            issuerCertificate: new Certificate_1.default(new pkijs.Certificate()),
        });
        expect(mockCertificateIssue).toBeCalledTimes(1);
        expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('pathLenConstraint', 1);
    });
});
describe('issueEndpointCertificate', () => {
    let minimalCertificateOptions;
    beforeAll(() => {
        minimalCertificateOptions = {
            issuerPrivateKey: stubSubjectKeyPair.privateKey,
            subjectPublicKey: stubSubjectKeyPair.publicKey,
            validityEndDate: new Date(),
        };
    });
    test('Certificate should be a valid X.509 certificate', async () => {
        const certificate = await (0, issuance_1.issueEndpointCertificate)(minimalCertificateOptions);
        expect(certificate).toBe(stubCertificate);
    });
    test('Certificate should honor all the basic options', async () => {
        await (0, issuance_1.issueEndpointCertificate)({ ...minimalCertificateOptions, ...basicCertificateOptions });
        expect(mockCertificateIssue.mock.calls[0][0]).toMatchObject(basicCertificateOptions);
    });
    test('Certificate should have its private address as its Common Name (CN)', async () => {
        await (0, issuance_1.issueEndpointCertificate)(minimalCertificateOptions);
        expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('commonName', `0${await (0, keys_1.getPublicKeyDigestHex)(stubSubjectKeyPair.publicKey)}`);
    });
    test('Certificate can be self-issued', async () => {
        expect(minimalCertificateOptions).not.toHaveProperty('issuerCertificate');
        await (0, issuance_1.issueEndpointCertificate)(minimalCertificateOptions);
    });
    test('Certificate can be issued by a gateway', async () => {
        const gatewayCertificate = new Certificate_1.default(new pkijs.Certificate());
        await (0, issuance_1.issueEndpointCertificate)({
            ...minimalCertificateOptions,
            issuerCertificate: gatewayCertificate,
        });
        expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('issuerCertificate', gatewayCertificate);
    });
    test('Subject should be marked as CA', async () => {
        await (0, issuance_1.issueEndpointCertificate)(minimalCertificateOptions);
        expect(mockCertificateIssue).toBeCalledTimes(1);
        expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('isCA', true);
    });
    test('pathLenConstraint should be 0', async () => {
        await (0, issuance_1.issueEndpointCertificate)(minimalCertificateOptions);
        expect(mockCertificateIssue).toBeCalledTimes(1);
        expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('pathLenConstraint', 0);
    });
});
describe('issueDeliveryAuthorization', () => {
    let minimalCertificateOptions;
    beforeAll(async () => {
        const authorizerKeyPair = await (0, keys_1.generateRSAKeyPair)();
        minimalCertificateOptions = {
            issuerCertificate: await (0, _test_utils_1.generateStubCert)({
                attributes: { isCA: true },
                issuerPrivateKey: authorizerKeyPair.privateKey,
                subjectPublicKey: authorizerKeyPair.publicKey,
            }),
            issuerPrivateKey: authorizerKeyPair.privateKey,
            subjectPublicKey: stubSubjectKeyPair.publicKey,
            validityEndDate: new Date(),
        };
    });
    test('Certificate should be a valid X.509 certificate', async () => {
        const certificate = await (0, issuance_1.issueDeliveryAuthorization)(minimalCertificateOptions);
        expect(certificate).toBe(stubCertificate);
    });
    test('Certificate should honor all the basic options', async () => {
        await (0, issuance_1.issueDeliveryAuthorization)({ ...minimalCertificateOptions, ...basicCertificateOptions });
        expect(mockCertificateIssue.mock.calls[0][0]).toMatchObject(basicCertificateOptions);
    });
    test('Certificate should have its private address as its Common Name (CN)', async () => {
        await (0, issuance_1.issueDeliveryAuthorization)(minimalCertificateOptions);
        expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('commonName', `0${await (0, keys_1.getPublicKeyDigestHex)(stubSubjectKeyPair.publicKey)}`);
    });
    test('Subject should not be marked as CA', async () => {
        await (0, issuance_1.issueDeliveryAuthorization)(minimalCertificateOptions);
        expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('isCA', false);
    });
    test('pathLenConstraint should be 0', async () => {
        await (0, issuance_1.issueDeliveryAuthorization)(minimalCertificateOptions);
        expect(mockCertificateIssue.mock.calls[0][0]).toHaveProperty('pathLenConstraint', 0);
    });
});
//# sourceMappingURL=issuance.spec.js.map