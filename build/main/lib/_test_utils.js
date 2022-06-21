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
exports.getAsn1SequenceItem = exports.asyncIterableToArray = exports.arrayToAsyncIterable = exports.arrayBufferFrom = exports.reSerializeCertificate = exports.getMockContext = exports.getMockInstance = exports.expectArrayBuffersToEqual = exports.catchError = exports.getPromiseRejection = exports.mockSpy = exports.sha256Hex = exports.calculateDigestHex = exports.generateStubCert = exports.expectAsn1ValuesToBeEqual = exports.expectPkijsValuesToBeEqual = exports.CRYPTO_OIDS = void 0;
const asn1js = __importStar(require("asn1js"));
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const crypto_1 = require("crypto");
const keys_1 = require("./crypto_wrappers/keys");
const Certificate_1 = __importDefault(require("./crypto_wrappers/x509/Certificate"));
exports.CRYPTO_OIDS = {
    AES_CBC_128: '2.16.840.1.101.3.4.1.2',
    AES_CBC_192: '2.16.840.1.101.3.4.1.22',
    AES_CBC_256: '2.16.840.1.101.3.4.1.42',
};
function expectPkijsValuesToBeEqual(expectedValue, actualValue) {
    expectAsn1ValuesToBeEqual(expectedValue.toSchema(), actualValue.toSchema());
}
exports.expectPkijsValuesToBeEqual = expectPkijsValuesToBeEqual;
function expectAsn1ValuesToBeEqual(expectedValue, actualValue) {
    expectArrayBuffersToEqual(expectedValue.toBER(false), actualValue.toBER(false));
}
exports.expectAsn1ValuesToBeEqual = expectAsn1ValuesToBeEqual;
/**
 * @deprecated Use {Certificate.issue} instead
 */
async function generateStubCert(config = {}) {
    const keyPair = await (0, keys_1.generateRSAKeyPair)();
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 1);
    futureDate.setMilliseconds(0);
    const subjectPublicKey = config.subjectPublicKey || keyPair.publicKey;
    const certificate = await Certificate_1.default.issue({
        commonName: `0${await (0, keys_1.getPublicKeyDigestHex)(subjectPublicKey)}`,
        issuerCertificate: config.issuerCertificate,
        issuerPrivateKey: config.issuerPrivateKey || keyPair.privateKey,
        subjectPublicKey,
        validityEndDate: futureDate,
        ...config.attributes,
    });
    return reSerializeCertificate(certificate);
}
exports.generateStubCert = generateStubCert;
function calculateDigestHex(algorithm, plaintext) {
    return (0, crypto_1.createHash)(algorithm).update(Buffer.from(plaintext)).digest('hex');
}
exports.calculateDigestHex = calculateDigestHex;
function sha256Hex(plaintext) {
    return calculateDigestHex('sha256', plaintext);
}
exports.sha256Hex = sha256Hex;
// tslint:disable-next-line:readonly-array
function mockSpy(spy, mockImplementation) {
    beforeEach(() => {
        spy.mockReset();
        if (mockImplementation) {
            spy.mockImplementation(mockImplementation);
        }
    });
    afterAll(() => {
        spy.mockRestore();
    });
    return spy;
}
exports.mockSpy = mockSpy;
async function getPromiseRejection(promise) {
    try {
        await promise;
    }
    catch (error) {
        return error;
    }
    throw new Error('Expected promise to throw');
}
exports.getPromiseRejection = getPromiseRejection;
function catchError(func, errorClass) {
    try {
        func();
    }
    catch (error) {
        if (!(error instanceof errorClass)) {
            throw error;
        }
        return error;
    }
    throw new Error('Expected function to throw');
}
exports.catchError = catchError;
/**
 * Assert that two `ArrayBuffer`s are equivalent.
 *
 * expect(value1).toEqual(value2) does NOT work with ArrayBuffer instances: It always passes.
 *
 * @param expectedBuffer
 * @param actualBuffer
 */
function expectArrayBuffersToEqual(expectedBuffer, actualBuffer) {
    expect(expectedBuffer).not.toBeInstanceOf(Buffer);
    expect(actualBuffer).not.toBeInstanceOf(Buffer);
    expect(Buffer.from(actualBuffer)).toEqual(Buffer.from(expectedBuffer));
}
exports.expectArrayBuffersToEqual = expectArrayBuffersToEqual;
function getMockInstance(mockedObject) {
    return mockedObject;
}
exports.getMockInstance = getMockInstance;
function getMockContext(mockedObject) {
    const mockInstance = getMockInstance(mockedObject);
    return mockInstance.mock;
}
exports.getMockContext = getMockContext;
function reSerializeCertificate(cert) {
    // TODO: Raise bug in PKI.js project
    // PKI.js sometimes tries to use attributes that are only set *after* the certificate has been
    // deserialized, so you'd get a TypeError if you use a certificate you just created in memory.
    // For example, `extension.parsedValue` would be `undefined` in
    // https://github.com/PeculiarVentures/PKI.js/blob/9a39551aa9f1445406f96680318014c8d714e8e3/src/CertificateChainValidationEngine.js#L155
    return Certificate_1.default.deserialize(cert.serialize());
}
exports.reSerializeCertificate = reSerializeCertificate;
function arrayBufferFrom(input) {
    return (0, buffer_to_arraybuffer_1.default)(Buffer.from(input));
}
exports.arrayBufferFrom = arrayBufferFrom;
async function* arrayToAsyncIterable(array) {
    for (const item of array) {
        yield item;
    }
}
exports.arrayToAsyncIterable = arrayToAsyncIterable;
async function asyncIterableToArray(iterable) {
    // tslint:disable-next-line:readonly-array
    const values = [];
    for await (const value of iterable) {
        values.push(value);
    }
    return values;
}
exports.asyncIterableToArray = asyncIterableToArray;
function getAsn1SequenceItem(fields, itemIndex) {
    expect(fields).toBeInstanceOf(asn1js.Sequence);
    const itemBlock = fields.valueBlock.value[itemIndex];
    expect(itemBlock).toBeInstanceOf(asn1js.Primitive);
    expect(itemBlock.idBlock.tagClass).toEqual(3); // Context-specific
    expect(itemBlock.idBlock.tagNumber).toEqual(itemIndex);
    return itemBlock;
}
exports.getAsn1SequenceItem = getAsn1SequenceItem;
//# sourceMappingURL=_test_utils.js.map