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
const asn1js = __importStar(require("asn1js"));
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const date_fns_1 = require("date-fns");
const jestDateMock = __importStar(require("jest-date-mock"));
const pkijs = __importStar(require("pkijs"));
const _test_utils_1 = require("../../_test_utils");
const oids = __importStar(require("../../oids"));
const _utils_1 = require("../_utils");
const keys_1 = require("../keys");
const Certificate_1 = __importDefault(require("./Certificate"));
const CertificateError_1 = __importDefault(require("./CertificateError"));
const pkijsCrypto = (0, _utils_1.getPkijsCrypto)();
const baseCertificateOptions = {
    commonName: 'the CN',
    validityEndDate: (0, date_fns_1.addDays)(new Date(), 1),
};
let issuerKeyPair;
let issuerCertificate;
let subjectKeyPair;
beforeAll(async () => {
    issuerKeyPair = await (0, keys_1.generateRSAKeyPair)();
    issuerCertificate = await Certificate_1.default.issue({
        ...baseCertificateOptions,
        isCA: true,
        issuerPrivateKey: issuerKeyPair.privateKey,
        subjectPublicKey: issuerKeyPair.publicKey,
    });
    subjectKeyPair = await (0, keys_1.generateRSAKeyPair)();
});
afterEach(() => {
    jest.restoreAllMocks();
    jestDateMock.clear();
});
describe('deserialize()', () => {
    test('should deserialize valid DER-encoded certificates', async () => {
        // Serialize manually just in this test to avoid depending on .serialize()
        const pkijsCert = (await (0, _test_utils_1.generateStubCert)()).pkijsCertificate;
        const certDer = pkijsCert.toSchema(true).toBER(false);
        const cert = Certificate_1.default.deserialize(certDer);
        expect(cert.pkijsCertificate.subject.typesAndValues[0].type).toBe(pkijsCert.subject.typesAndValues[0].type);
        expect(cert.pkijsCertificate.subject.typesAndValues[0].value.valueBlock.value).toBe(pkijsCert.subject.typesAndValues[0].value.valueBlock.value);
    });
    test('should error out with invalid DER values', () => {
        const invalidDer = (0, buffer_to_arraybuffer_1.default)(Buffer.from('nope'));
        expect(() => Certificate_1.default.deserialize(invalidDer)).toThrowWithMessage(Error, 'Value is not DER-encoded');
    });
});
describe('issue()', () => {
    test('should create an X.509 v3 certificate', async () => {
        const cert = await Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
        });
        // v3 is serialized as integer 2
        expect(cert.pkijsCertificate.version).toBe(2);
    });
    test('should import the public key into the certificate', async () => {
        jest.spyOn(pkijs.PublicKeyInfo.prototype, 'importKey');
        await Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
        });
        expect(pkijs.PublicKeyInfo.prototype.importKey).toBeCalledTimes(1);
        expect(pkijs.PublicKeyInfo.prototype.importKey).toBeCalledWith(subjectKeyPair.publicKey);
    });
    test('should be signed with the specified private key', async () => {
        jest.spyOn(pkijs.Certificate.prototype, 'sign');
        await Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
        });
        expect(pkijs.Certificate.prototype.sign).toBeCalledTimes(1);
        expect(pkijs.Certificate.prototype.sign).toBeCalledWith(subjectKeyPair.privateKey, subjectKeyPair.privateKey.algorithm.hash.name);
    });
    test('should generate a positive serial number', async () => {
        let anySignFlipped = false;
        for (let index = 0; index < 10; index++) {
            const cert = await Certificate_1.default.issue({
                ...baseCertificateOptions,
                issuerPrivateKey: subjectKeyPair.privateKey,
                subjectPublicKey: subjectKeyPair.publicKey,
            });
            const serialNumberSerialized = new Uint8Array(cert.pkijsCertificate.serialNumber.valueBlock.valueHex);
            if (serialNumberSerialized.length === 9) {
                expect(serialNumberSerialized[0]).toEqual(0);
                anySignFlipped = true;
            }
            else {
                expect(serialNumberSerialized).toHaveLength(8);
                expect(serialNumberSerialized[0]).toBeGreaterThanOrEqual(0);
                expect(serialNumberSerialized[0]).toBeLessThanOrEqual(127);
            }
        }
        expect(anySignFlipped).toBeTrue();
    });
    test('should create a certificate valid from now by default', async () => {
        const now = new Date();
        now.setMilliseconds(1); // We need to check it's rounded down to the nearest second
        jestDateMock.advanceTo(now);
        const cert = await Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
        });
        const expectedDate = new Date(now.getTime());
        expectedDate.setMilliseconds(0);
        expect(cert.startDate).toEqual(expectedDate);
    });
    test('should honor a custom start validity date', async () => {
        const startDate = new Date(2019, 1, 1, 1, 1, 1, 1);
        const cert = await Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
            validityStartDate: startDate,
        });
        const expectedDate = new Date(startDate.getTime());
        expectedDate.setMilliseconds(0);
        expect(cert.startDate).toEqual(expectedDate);
    });
    test('should refuse start date if after expiry date of issuer', async () => {
        const startDate = (0, date_fns_1.addSeconds)(issuerCertificate.expiryDate, 1);
        const expiryDate = (0, date_fns_1.addSeconds)(startDate, 1);
        await expect(Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerCertificate,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
            validityEndDate: expiryDate,
            validityStartDate: startDate,
        })).rejects.toThrow('The end date must be later than the start date');
    });
    describe('Validity end date', () => {
        test('should honor explicit one', async () => {
            const endDate = (0, date_fns_1.setMilliseconds)((0, date_fns_1.addDays)(new Date(), 1), 0);
            const cert = await Certificate_1.default.issue({
                ...baseCertificateOptions,
                issuerPrivateKey: subjectKeyPair.privateKey,
                subjectPublicKey: subjectKeyPair.publicKey,
                validityEndDate: endDate,
            });
            expect(cert.expiryDate).toEqual(endDate);
        });
        test('should be capped at that of issuer', async () => {
            const endDate = (0, date_fns_1.addSeconds)(issuerCertificate.expiryDate, 1);
            const cert = await Certificate_1.default.issue({
                ...baseCertificateOptions,
                issuerCertificate,
                issuerPrivateKey: subjectKeyPair.privateKey,
                subjectPublicKey: subjectKeyPair.publicKey,
                validityEndDate: endDate,
            });
            expect(cert.expiryDate).toEqual(issuerCertificate.expiryDate);
        });
        test('should be rounded down to nearest second', async () => {
            const endDate = (0, date_fns_1.addDays)(issuerCertificate.expiryDate, 1);
            const cert = await Certificate_1.default.issue({
                ...baseCertificateOptions,
                issuerPrivateKey: subjectKeyPair.privateKey,
                subjectPublicKey: subjectKeyPair.publicKey,
                validityEndDate: endDate,
            });
            expect(cert.expiryDate).toEqual((0, date_fns_1.setMilliseconds)(endDate, 0));
        });
        test('should be refused if before the start date', async () => {
            const startDate = new Date(2019, 1, 1);
            const invalidEndDate = (0, date_fns_1.subSeconds)(new Date(startDate), 1);
            await expect(Certificate_1.default.issue({
                ...baseCertificateOptions,
                issuerPrivateKey: subjectKeyPair.privateKey,
                subjectPublicKey: subjectKeyPair.publicKey,
                validityEndDate: invalidEndDate,
                validityStartDate: startDate,
            })).rejects.toThrow('The end date must be later than the start date');
        });
    });
    test('should store the specified Common Name (CN) in the subject', async () => {
        const commonName = 'this is the CN';
        const cert = await Certificate_1.default.issue({
            ...baseCertificateOptions,
            commonName,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
        });
        const subjectDnAttributes = cert.pkijsCertificate.subject.typesAndValues;
        expect(subjectDnAttributes.length).toBe(1);
        expect(subjectDnAttributes[0].type).toBe(oids.COMMON_NAME);
        expect(subjectDnAttributes[0].value.valueBlock.value).toEqual(commonName);
    });
    test('should set issuer DN to that of subject when self-issuing certificates', async () => {
        const cert = await Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
        });
        const subjectDn = cert.pkijsCertificate.subject.typesAndValues;
        const issuerDn = cert.pkijsCertificate.issuer.typesAndValues;
        expect(issuerDn.length).toBe(1);
        expect(issuerDn[0].type).toBe(oids.COMMON_NAME);
        expect(issuerDn[0].value.valueBlock.value).toBe(subjectDn[0].value.valueBlock.value);
    });
    test('should accept an issuer marked as CA', async () => {
        const issuerCert = await Certificate_1.default.issue({
            ...baseCertificateOptions,
            isCA: true,
            issuerPrivateKey: issuerKeyPair.privateKey,
            subjectPublicKey: issuerKeyPair.publicKey,
        });
        await expect(Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerCertificate: issuerCert,
            issuerPrivateKey: issuerKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
        })).toResolve();
    });
    test('should refuse an issuer certificate without extensions', async () => {
        const invalidIssuerCertificate = await Certificate_1.default.issue({
            ...baseCertificateOptions,
            isCA: false,
            issuerPrivateKey: issuerKeyPair.privateKey,
            subjectPublicKey: issuerKeyPair.publicKey,
        });
        // tslint:disable-next-line:no-object-mutation
        invalidIssuerCertificate.pkijsCertificate.extensions = undefined;
        await expect(Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerCertificate: invalidIssuerCertificate,
            issuerPrivateKey: issuerKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
        })).rejects.toEqual(new CertificateError_1.default('Basic constraints extension is missing from issuer certificate'));
    });
    test('should refuse an issuer certificate with an empty set of extensions', async () => {
        const invalidIssuerCertificate = await Certificate_1.default.issue({
            ...baseCertificateOptions,
            isCA: false,
            issuerPrivateKey: issuerKeyPair.privateKey,
            subjectPublicKey: issuerKeyPair.publicKey,
        });
        // tslint:disable-next-line:no-object-mutation
        invalidIssuerCertificate.pkijsCertificate.extensions = [];
        await expect(Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerCertificate: invalidIssuerCertificate,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
        })).rejects.toEqual(new CertificateError_1.default('Basic constraints extension is missing from issuer certificate'));
    });
    test('should refuse an issuer certificate without basic constraints extension', async () => {
        const invalidIssuerCertificate = await Certificate_1.default.issue({
            ...baseCertificateOptions,
            isCA: false,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: issuerKeyPair.publicKey,
        });
        // tslint:disable-next-line:no-object-mutation
        invalidIssuerCertificate.pkijsCertificate.extensions = invalidIssuerCertificate.pkijsCertificate.extensions.filter((e) => e.extnID !== oids.BASIC_CONSTRAINTS);
        await expect(Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerCertificate: invalidIssuerCertificate,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
        })).rejects.toEqual(new CertificateError_1.default('Basic constraints extension is missing from issuer certificate'));
    });
    test('should refuse an issuer not marked as CA', async () => {
        const invalidIssuerCertificate = await Certificate_1.default.issue({
            ...baseCertificateOptions,
            isCA: false,
            issuerPrivateKey: issuerKeyPair.privateKey,
            subjectPublicKey: issuerKeyPair.publicKey,
        });
        await expect(Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerCertificate: invalidIssuerCertificate,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
        })).rejects.toEqual(new CertificateError_1.default('Issuer is not a CA'));
    });
    test('should set issuer DN to that of CA', async () => {
        const subjectCert = await Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerCertificate,
            issuerPrivateKey: issuerKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
        });
        const subjectCertIssuerDn = subjectCert.pkijsCertificate.issuer.typesAndValues;
        expect(subjectCertIssuerDn.length).toBe(1);
        expect(subjectCertIssuerDn[0].type).toBe(oids.COMMON_NAME);
        const issuerCn = issuerCertificate.pkijsCertificate.subject.typesAndValues[0].value.valueBlock.value;
        expect(subjectCertIssuerDn[0].value.valueBlock.value).toBe(issuerCn);
    });
    describe('Basic Constraints extension', () => {
        test('Extension should be included and marked as critical', async () => {
            const cert = await Certificate_1.default.issue({
                ...baseCertificateOptions,
                issuerPrivateKey: subjectKeyPair.privateKey,
                subjectPublicKey: subjectKeyPair.publicKey,
            });
            const extensions = cert.pkijsCertificate.extensions;
            const matchingExtensions = extensions.filter((e) => e.extnID === oids.BASIC_CONSTRAINTS);
            expect(matchingExtensions).toHaveLength(1);
            expect(matchingExtensions[0]).toHaveProperty('critical', true);
        });
        test('CA flag should be false by default', async () => {
            const cert = await Certificate_1.default.issue({
                ...baseCertificateOptions,
                issuerPrivateKey: subjectKeyPair.privateKey,
                subjectPublicKey: subjectKeyPair.publicKey,
            });
            const basicConstraints = getBasicConstraintsExtension(cert);
            expect(basicConstraints).toHaveProperty('cA', false);
        });
        test('CA flag should be enabled if requested', async () => {
            const cert = await Certificate_1.default.issue({
                ...baseCertificateOptions,
                isCA: true,
                issuerPrivateKey: subjectKeyPair.privateKey,
                subjectPublicKey: subjectKeyPair.publicKey,
            });
            const basicConstraints = getBasicConstraintsExtension(cert);
            expect(basicConstraints).toHaveProperty('cA', true);
        });
        test('pathLenConstraint should be 0 by default', async () => {
            const cert = await Certificate_1.default.issue({
                ...baseCertificateOptions,
                issuerPrivateKey: subjectKeyPair.privateKey,
                subjectPublicKey: subjectKeyPair.publicKey,
            });
            const basicConstraints = getBasicConstraintsExtension(cert);
            expect(basicConstraints).toHaveProperty('pathLenConstraint', 0);
        });
        test('pathLenConstraint can be set to a custom value <= 2', async () => {
            const pathLenConstraint = 2;
            const cert = await Certificate_1.default.issue({
                ...baseCertificateOptions,
                issuerPrivateKey: subjectKeyPair.privateKey,
                pathLenConstraint,
                subjectPublicKey: subjectKeyPair.publicKey,
            });
            const basicConstraints = getBasicConstraintsExtension(cert);
            expect(basicConstraints).toHaveProperty('pathLenConstraint', pathLenConstraint);
        });
        test('pathLenConstraint should not be greater than 2', async () => {
            await expect(Certificate_1.default.issue({
                ...baseCertificateOptions,
                issuerPrivateKey: subjectKeyPair.privateKey,
                pathLenConstraint: 3,
                subjectPublicKey: subjectKeyPair.publicKey,
            })).rejects.toEqual(new CertificateError_1.default('pathLenConstraint must be between 0 and 2 (got 3)'));
        });
        test('pathLenConstraint should not be negative', async () => {
            await expect(Certificate_1.default.issue({
                ...baseCertificateOptions,
                issuerPrivateKey: subjectKeyPair.privateKey,
                pathLenConstraint: -1,
                subjectPublicKey: subjectKeyPair.publicKey,
            })).rejects.toEqual(new CertificateError_1.default('pathLenConstraint must be between 0 and 2 (got -1)'));
        });
    });
    describe('Authority Key Identifier extension', () => {
        test('should correspond to subject when self-issued', async () => {
            const cert = await Certificate_1.default.issue({
                ...baseCertificateOptions,
                issuerPrivateKey: subjectKeyPair.privateKey,
                subjectPublicKey: subjectKeyPair.publicKey,
            });
            const extensions = cert.pkijsCertificate.extensions || [];
            const matchingExtensions = extensions.filter((e) => e.extnID === oids.AUTHORITY_KEY);
            expect(matchingExtensions).toHaveLength(1);
            const akiExtension = matchingExtensions[0];
            expect(akiExtension.critical).toBe(false);
            const akiExtensionAsn1 = (0, _utils_1.derDeserialize)(akiExtension.extnValue.valueBlock.valueHex);
            const akiExtensionRestored = new pkijs.AuthorityKeyIdentifier({
                schema: akiExtensionAsn1,
            });
            if (!akiExtensionRestored.keyIdentifier) {
                throw new Error('akiExtensionRestored.keyIdentifier is empty');
            }
            const keyIdBuffer = Buffer.from(akiExtensionRestored.keyIdentifier.valueBlock.valueHex);
            expect(keyIdBuffer.toString('hex')).toEqual(await getPublicKeyDigest(subjectKeyPair.publicKey));
        });
        test('should correspond to issuer key when different from subject', async () => {
            const subjectCert = await Certificate_1.default.issue({
                ...baseCertificateOptions,
                issuerCertificate,
                issuerPrivateKey: subjectKeyPair.privateKey,
                subjectPublicKey: subjectKeyPair.publicKey,
            });
            const extensions = subjectCert.pkijsCertificate.extensions || [];
            const matchingExtensions = extensions.filter((e) => e.extnID === oids.AUTHORITY_KEY);
            expect(matchingExtensions).toHaveLength(1);
            const akiExtension = matchingExtensions[0];
            expect(akiExtension.critical).toBe(false);
            const akiExtensionAsn1 = (0, _utils_1.derDeserialize)(akiExtension.extnValue.valueBlock.valueHex);
            const akiExtensionRestored = new pkijs.AuthorityKeyIdentifier({
                schema: akiExtensionAsn1,
            });
            if (!akiExtensionRestored.keyIdentifier) {
                throw new Error('akiExtensionRestored.keyIdentifier is empty');
            }
            const keyIdBuffer = Buffer.from(akiExtensionRestored.keyIdentifier.valueBlock.valueHex);
            expect(keyIdBuffer.toString('hex')).toEqual(await getPublicKeyDigest(issuerKeyPair.publicKey));
        });
    });
    test('Subject Key Identifier extension should correspond to subject key', async () => {
        const subjectCert = await Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerCertificate,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
        });
        const extensions = subjectCert.pkijsCertificate.extensions || [];
        const matchingExtensions = extensions.filter((e) => e.extnID === oids.SUBJECT_KEY);
        expect(matchingExtensions).toHaveLength(1);
        const skiExtension = matchingExtensions[0];
        expect(skiExtension.critical).toBe(false);
        const skiExtensionAsn1 = (0, _utils_1.derDeserialize)(skiExtension.extnValue.valueBlock.valueHex);
        expect(skiExtensionAsn1).toBeInstanceOf(asn1js.OctetString);
        // @ts-ignore
        const keyIdBuffer = Buffer.from(skiExtensionAsn1.valueBlock.valueHex);
        expect(keyIdBuffer.toString('hex')).toEqual(await getPublicKeyDigest(subjectKeyPair.publicKey));
    });
});
test('serialize() should return a DER-encoded buffer', async () => {
    const cert = await (0, _test_utils_1.generateStubCert)();
    const certDer = cert.serialize();
    const asn1Value = (0, _utils_1.derDeserialize)(certDer);
    const pkijsCert = new pkijs.Certificate({ schema: asn1Value });
    const subjectDnAttributes = pkijsCert.subject.typesAndValues;
    expect(subjectDnAttributes.length).toBe(1);
    expect(subjectDnAttributes[0].type).toBe(oids.COMMON_NAME);
    expect(subjectDnAttributes[0].value.valueBlock.value).toBe(cert.getCommonName());
    const issuerDnAttributes = pkijsCert.issuer.typesAndValues;
    expect(issuerDnAttributes.length).toBe(1);
    expect(issuerDnAttributes[0].type).toBe(oids.COMMON_NAME);
    expect(issuerDnAttributes[0].value.valueBlock.value).toBe(cert.getCommonName());
});
test('startDate should return the start date', async () => {
    const cert = await (0, _test_utils_1.generateStubCert)();
    const expectedStartDate = cert.pkijsCertificate.notBefore.value;
    expect(cert.startDate).toEqual(expectedStartDate);
});
describe('expiryDate', () => {
    test('should return the expiry date', async () => {
        const expiryDate = (0, date_fns_1.setMilliseconds)(new Date(), 0);
        const cert = await Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
            validityEndDate: expiryDate,
        });
        expect(cert.expiryDate).toEqual(expiryDate);
    });
    test('should round down to the nearest second', async () => {
        const expiryDate = (0, date_fns_1.setMilliseconds)((0, date_fns_1.addSeconds)(new Date(), 10), 50);
        const cert = await Certificate_1.default.issue({
            ...baseCertificateOptions,
            issuerPrivateKey: subjectKeyPair.privateKey,
            subjectPublicKey: subjectKeyPair.publicKey,
            validityEndDate: expiryDate,
        });
        expect(cert.expiryDate).toEqual((0, date_fns_1.setMilliseconds)(expiryDate, 0));
    });
});
test('getSerialNumber() should return the serial number as a buffer', async () => {
    const cert = await (0, _test_utils_1.generateStubCert)();
    const serialNumberBuffer = cert.getSerialNumber();
    expect(serialNumberBuffer).toEqual(Buffer.from(cert.pkijsCertificate.serialNumber.valueBlock.valueHex));
});
test('getSerialNumberHex() should return the hex representation of serial number', async () => {
    const cert = await (0, _test_utils_1.generateStubCert)();
    const serialNumberHex = cert.getSerialNumberHex();
    expect(Buffer.from(serialNumberHex, 'hex')).toEqual(cert.getSerialNumber());
});
describe('getCommonName()', () => {
    test('should return the address when found', async () => {
        const cert = await (0, _test_utils_1.generateStubCert)();
        const subjectDn = cert.pkijsCertificate.subject.typesAndValues;
        expect(cert.getCommonName()).toEqual(subjectDn[0].value.valueBlock.value);
    });
    test('should error out when the address is not found', async () => {
        const cert = await (0, _test_utils_1.generateStubCert)();
        // tslint:disable-next-line:no-object-mutation
        cert.pkijsCertificate.subject.typesAndValues = [];
        expect(() => cert.getCommonName()).toThrowWithMessage(CertificateError_1.default, 'Distinguished Name does not contain Common Name');
    });
});
describe('calculateSubjectPrivateAddress', () => {
    test('Private node address should be returned', async () => {
        const nodeKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const nodeCertificate = await (0, _test_utils_1.generateStubCert)({
            issuerPrivateKey: nodeKeyPair.privateKey,
            subjectPublicKey: nodeKeyPair.publicKey,
        });
        await expect(nodeCertificate.calculateSubjectPrivateAddress()).resolves.toEqual(await (0, keys_1.getPrivateAddressFromIdentityKey)(nodeKeyPair.publicKey));
    });
    test('Computation should be cached', async () => {
        const nodeKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const nodeCertificate = await (0, _test_utils_1.generateStubCert)({
            issuerPrivateKey: nodeKeyPair.privateKey,
            subjectPublicKey: nodeKeyPair.publicKey,
        });
        const getPublicKeySpy = jest.spyOn(nodeCertificate, 'getPublicKey');
        const address = await nodeCertificate.calculateSubjectPrivateAddress();
        await expect(nodeCertificate.calculateSubjectPrivateAddress()).resolves.toEqual(address);
        expect(getPublicKeySpy).toBeCalledTimes(1);
    });
});
describe('getIssuerPrivateAddress', () => {
    test('Nothing should be output if there are no extensions', async () => {
        const certificate = await (0, _test_utils_1.generateStubCert)({});
        // tslint:disable-next-line:no-delete no-object-mutation
        delete certificate.pkijsCertificate.extensions;
        expect(certificate.getIssuerPrivateAddress()).toBeNull();
    });
    test('Nothing should be output if extension is missing', async () => {
        const certificate = await (0, _test_utils_1.generateStubCert)({});
        // tslint:disable-next-line:no-object-mutation
        certificate.pkijsCertificate.extensions = certificate.pkijsCertificate.extensions.filter((e) => e.extnID !== oids.AUTHORITY_KEY);
        expect(certificate.getIssuerPrivateAddress()).toBeNull();
    });
    test('Private address of issuer should be output if extension is present', async () => {
        const certificate = await (0, _test_utils_1.generateStubCert)({
            issuerCertificate,
            issuerPrivateKey: issuerKeyPair.privateKey,
        });
        expect(certificate.getIssuerPrivateAddress()).toEqual(await issuerCertificate.calculateSubjectPrivateAddress());
    });
});
describe('isEqual', () => {
    test('Equal certificates should be reported as such', async () => {
        const cert1 = await (0, _test_utils_1.generateStubCert)();
        const cert2 = Certificate_1.default.deserialize(cert1.serialize());
        expect(cert1.isEqual(cert2)).toBeTrue();
    });
    test('Different certificates should be reported as such', async () => {
        const cert1 = await (0, _test_utils_1.generateStubCert)();
        const cert2 = await (0, _test_utils_1.generateStubCert)();
        expect(cert1.isEqual(cert2)).toBeFalse();
    });
});
describe('validate()', () => {
    test('Valid certificates should be accepted', async () => {
        const cert = await (0, _test_utils_1.generateStubCert)();
        cert.validate();
    });
    test('Certificate version other than 3 should be refused', async () => {
        const cert = await (0, _test_utils_1.generateStubCert)();
        // tslint:disable-next-line:no-object-mutation
        cert.pkijsCertificate.version = 1;
        expect(() => cert.validate()).toThrowWithMessage(CertificateError_1.default, 'Only X.509 v3 certificates are supported (got v2)');
    });
    test('Certificate not yet valid should not be accepted', async () => {
        const validityStartDate = new Date();
        validityStartDate.setMinutes(validityStartDate.getMinutes() + 5);
        const validityEndDate = new Date(validityStartDate);
        validityEndDate.setMinutes(validityEndDate.getMinutes() + 1);
        const cert = await (0, _test_utils_1.generateStubCert)({ attributes: { validityEndDate, validityStartDate } });
        expect(() => cert.validate()).toThrowWithMessage(CertificateError_1.default, 'Certificate is not yet valid');
    });
    test('Expired certificate should not be accepted', async () => {
        const validityEndDate = new Date();
        validityEndDate.setMinutes(validityEndDate.getMinutes() - 1);
        const validityStartDate = new Date(validityEndDate);
        validityStartDate.setMinutes(validityStartDate.getMinutes() - 1);
        const cert = await (0, _test_utils_1.generateStubCert)({ attributes: { validityEndDate, validityStartDate } });
        expect(() => cert.validate()).toThrowWithMessage(CertificateError_1.default, 'Certificate already expired');
    });
});
describe('getCertificationPath', () => {
    let stubTrustedCaPrivateKey;
    let stubRootCa;
    beforeAll(async () => {
        const trustedCaKeyPair = await (0, keys_1.generateRSAKeyPair)();
        stubTrustedCaPrivateKey = trustedCaKeyPair.privateKey;
        stubRootCa = (0, _test_utils_1.reSerializeCertificate)(await (0, _test_utils_1.generateStubCert)({
            attributes: { isCA: true },
            issuerPrivateKey: trustedCaKeyPair.privateKey,
            subjectPublicKey: trustedCaKeyPair.publicKey,
        }));
    });
    test('Cert issued by trusted cert should be trusted', async () => {
        const cert = (0, _test_utils_1.reSerializeCertificate)(await (0, _test_utils_1.generateStubCert)({
            issuerCertificate: stubRootCa,
            issuerPrivateKey: stubTrustedCaPrivateKey,
        }));
        await expect(cert.getCertificationPath([], [stubRootCa])).resolves.toEqual([cert, stubRootCa]);
    });
    test('Cert not issued by trusted cert should not be trusted', async () => {
        const cert = await (0, _test_utils_1.generateStubCert)();
        await expect(cert.getCertificationPath([], [stubRootCa])).rejects.toEqual(new CertificateError_1.default('No valid certificate paths found'));
    });
    test('Expired certificate should not be trusted', async () => {
        const validityEndDate = new Date();
        validityEndDate.setMinutes(validityEndDate.getMinutes() - 1);
        const validityStartDate = new Date(validityEndDate);
        validityStartDate.setMinutes(validityStartDate.getMinutes() - 1);
        const cert = await (0, _test_utils_1.generateStubCert)({ attributes: { validityEndDate, validityStartDate } });
        await expect(cert.getCertificationPath([], [stubRootCa])).rejects.toEqual(new CertificateError_1.default('No valid certificate paths found'));
    });
    test('Cert issued by untrusted intermediate should be trusted if root is trusted', async () => {
        const intermediateCaKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const intermediateCaCert = (0, _test_utils_1.reSerializeCertificate)(await (0, _test_utils_1.generateStubCert)({
            attributes: { isCA: true },
            issuerCertificate: stubRootCa,
            issuerPrivateKey: stubTrustedCaPrivateKey,
            subjectPublicKey: intermediateCaKeyPair.publicKey,
        }));
        const cert = (0, _test_utils_1.reSerializeCertificate)(await (0, _test_utils_1.generateStubCert)({
            issuerCertificate: intermediateCaCert,
            issuerPrivateKey: intermediateCaKeyPair.privateKey,
        }));
        await expect(cert.getCertificationPath([intermediateCaCert], [stubRootCa])).resolves.toEqual([
            cert,
            intermediateCaCert,
            stubRootCa,
        ]);
    });
    test('Cert issued by trusted intermediate CA should be trusted', async () => {
        const intermediateCaKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const intermediateCaCert = (0, _test_utils_1.reSerializeCertificate)(await (0, _test_utils_1.generateStubCert)({
            attributes: { isCA: true },
            issuerCertificate: stubRootCa,
            issuerPrivateKey: stubTrustedCaPrivateKey,
            subjectPublicKey: intermediateCaKeyPair.publicKey,
        }));
        const cert = (0, _test_utils_1.reSerializeCertificate)(await (0, _test_utils_1.generateStubCert)({
            issuerCertificate: intermediateCaCert,
            issuerPrivateKey: intermediateCaKeyPair.privateKey,
        }));
        await expect(cert.getCertificationPath([], [intermediateCaCert])).resolves.toEqual([
            cert,
            intermediateCaCert,
        ]);
    });
    test('Cert issued by untrusted intermediate CA should not be trusted', async () => {
        const untrustedIntermediateCaKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const untrustedIntermediateCaCert = await (0, _test_utils_1.generateStubCert)({
            attributes: { isCA: true },
            issuerPrivateKey: untrustedIntermediateCaKeyPair.privateKey,
            subjectPublicKey: untrustedIntermediateCaKeyPair.publicKey,
        });
        const cert = (0, _test_utils_1.reSerializeCertificate)(await (0, _test_utils_1.generateStubCert)({
            issuerCertificate: untrustedIntermediateCaCert,
            issuerPrivateKey: untrustedIntermediateCaKeyPair.privateKey,
        }));
        await expect(cert.getCertificationPath([(0, _test_utils_1.reSerializeCertificate)(untrustedIntermediateCaCert)], [stubRootCa])).rejects.toEqual(new CertificateError_1.default('No valid certificate paths found'));
    });
    test('Including trusted intermediate CA should not make certificate trusted', async () => {
        const intermediateCaKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const trustedIntermediateCaCert = await (0, _test_utils_1.generateStubCert)({
            attributes: { isCA: true },
            issuerPrivateKey: intermediateCaKeyPair.privateKey,
            subjectPublicKey: intermediateCaKeyPair.publicKey,
        });
        const cert = await (0, _test_utils_1.generateStubCert)();
        await expect(cert.getCertificationPath([trustedIntermediateCaCert], [stubRootCa])).rejects.toEqual(new CertificateError_1.default('No valid certificate paths found'));
    });
    test('Root certificate should be ignored if passed as intermediate unnecessarily', async () => {
        const intermediateCaKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const intermediateCaCert = (0, _test_utils_1.reSerializeCertificate)(await (0, _test_utils_1.generateStubCert)({
            attributes: { isCA: true },
            issuerCertificate: stubRootCa,
            issuerPrivateKey: stubTrustedCaPrivateKey,
            subjectPublicKey: intermediateCaKeyPair.publicKey,
        }));
        const cert = (0, _test_utils_1.reSerializeCertificate)(await (0, _test_utils_1.generateStubCert)({
            issuerCertificate: intermediateCaCert,
            issuerPrivateKey: intermediateCaKeyPair.privateKey,
        }));
        await expect(cert.getCertificationPath([intermediateCaCert, stubRootCa], [intermediateCaCert])).resolves.toEqual([cert, intermediateCaCert]);
    });
});
test('getPublicKey should return the subject public key', async () => {
    const cert = await (0, _test_utils_1.generateStubCert)({
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
    });
    const publicKey = await cert.getPublicKey();
    await expect((0, keys_1.derSerializePublicKey)(publicKey)).resolves.toEqual(await (0, keys_1.derSerializePublicKey)(subjectKeyPair.publicKey));
});
function getBasicConstraintsExtension(cert) {
    const extensions = cert.pkijsCertificate.extensions;
    const matchingExtensions = extensions.filter((e) => e.extnID === oids.BASIC_CONSTRAINTS);
    const extension = matchingExtensions[0];
    const basicConstraintsAsn1 = (0, _utils_1.derDeserialize)(extension.extnValue.valueBlock.valueHex);
    return new pkijs.BasicConstraints({ schema: basicConstraintsAsn1 });
}
async function getPublicKeyDigest(publicKey) {
    // @ts-ignore
    const publicKeyDer = await pkijsCrypto.exportKey('spki', publicKey);
    return (0, _test_utils_1.sha256Hex)(publicKeyDer);
}
//# sourceMappingURL=Certificate.spec.js.map