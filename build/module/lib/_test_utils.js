import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import { createHash } from 'crypto';
import { generateRSAKeyPair, getPublicKeyDigestHex } from './crypto_wrappers/keys';
import Certificate from './crypto_wrappers/x509/Certificate';
export const CRYPTO_OIDS = {
    AES_CBC_128: '2.16.840.1.101.3.4.1.2',
    AES_CBC_192: '2.16.840.1.101.3.4.1.22',
    AES_CBC_256: '2.16.840.1.101.3.4.1.42',
};
export function expectPkijsValuesToBeEqual(expectedValue, actualValue) {
    expectAsn1ValuesToBeEqual(expectedValue.toSchema(), actualValue.toSchema());
}
export function expectAsn1ValuesToBeEqual(expectedValue, actualValue) {
    expectArrayBuffersToEqual(expectedValue.toBER(false), actualValue.toBER(false));
}
/**
 * @deprecated Use {Certificate.issue} instead
 */
export async function generateStubCert(config = {}) {
    const keyPair = await generateRSAKeyPair();
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 1);
    futureDate.setMilliseconds(0);
    const subjectPublicKey = config.subjectPublicKey || keyPair.publicKey;
    const certificate = await Certificate.issue({
        commonName: `0${await getPublicKeyDigestHex(subjectPublicKey)}`,
        issuerCertificate: config.issuerCertificate,
        issuerPrivateKey: config.issuerPrivateKey || keyPair.privateKey,
        subjectPublicKey,
        validityEndDate: futureDate,
        ...config.attributes,
    });
    return reSerializeCertificate(certificate);
}
export function calculateDigestHex(algorithm, plaintext) {
    return createHash(algorithm).update(Buffer.from(plaintext)).digest('hex');
}
export function sha256Hex(plaintext) {
    return calculateDigestHex('sha256', plaintext);
}
// tslint:disable-next-line:readonly-array
export function mockSpy(spy, mockImplementation) {
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
export async function getPromiseRejection(promise) {
    try {
        await promise;
    }
    catch (error) {
        return error;
    }
    throw new Error('Expected promise to throw');
}
export function catchError(func, errorClass) {
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
/**
 * Assert that two `ArrayBuffer`s are equivalent.
 *
 * expect(value1).toEqual(value2) does NOT work with ArrayBuffer instances: It always passes.
 *
 * @param expectedBuffer
 * @param actualBuffer
 */
export function expectArrayBuffersToEqual(expectedBuffer, actualBuffer) {
    expect(expectedBuffer).not.toBeInstanceOf(Buffer);
    expect(actualBuffer).not.toBeInstanceOf(Buffer);
    expect(Buffer.from(actualBuffer)).toEqual(Buffer.from(expectedBuffer));
}
export function getMockInstance(mockedObject) {
    return mockedObject;
}
export function getMockContext(mockedObject) {
    const mockInstance = getMockInstance(mockedObject);
    return mockInstance.mock;
}
export function reSerializeCertificate(cert) {
    // TODO: Raise bug in PKI.js project
    // PKI.js sometimes tries to use attributes that are only set *after* the certificate has been
    // deserialized, so you'd get a TypeError if you use a certificate you just created in memory.
    // For example, `extension.parsedValue` would be `undefined` in
    // https://github.com/PeculiarVentures/PKI.js/blob/9a39551aa9f1445406f96680318014c8d714e8e3/src/CertificateChainValidationEngine.js#L155
    return Certificate.deserialize(cert.serialize());
}
export function arrayBufferFrom(input) {
    return bufferToArray(Buffer.from(input));
}
export async function* arrayToAsyncIterable(array) {
    for (const item of array) {
        yield item;
    }
}
export async function asyncIterableToArray(iterable) {
    // tslint:disable-next-line:readonly-array
    const values = [];
    for await (const value of iterable) {
        values.push(value);
    }
    return values;
}
export function getAsn1SequenceItem(fields, itemIndex) {
    expect(fields).toBeInstanceOf(asn1js.Sequence);
    const itemBlock = fields.valueBlock.value[itemIndex];
    expect(itemBlock).toBeInstanceOf(asn1js.Primitive);
    expect(itemBlock.idBlock.tagClass).toEqual(3); // Context-specific
    expect(itemBlock.idBlock.tagNumber).toEqual(itemIndex);
    return itemBlock;
}
//# sourceMappingURL=_test_utils.js.map