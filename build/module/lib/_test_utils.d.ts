/// <reference types="node" />
/// <reference types="jest" />
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import Certificate from './crypto_wrappers/x509/Certificate';
import FullCertificateIssuanceOptions from './crypto_wrappers/x509/FullCertificateIssuanceOptions';
export declare const CRYPTO_OIDS: {
    AES_CBC_128: string;
    AES_CBC_192: string;
    AES_CBC_256: string;
};
declare type PkijsValueType = pkijs.RelativeDistinguishedNames | pkijs.Certificate;
export declare function expectPkijsValuesToBeEqual(expectedValue: PkijsValueType, actualValue: PkijsValueType): void;
declare type Asn1jsToBER = (sizeOnly?: boolean) => ArrayBuffer;
interface Asn1jsSerializable {
    readonly toBER: Asn1jsToBER;
}
export declare function expectAsn1ValuesToBeEqual(expectedValue: Asn1jsSerializable, actualValue: Asn1jsSerializable): void;
interface StubCertConfig {
    readonly attributes: Partial<FullCertificateIssuanceOptions>;
    readonly issuerCertificate: Certificate;
    readonly issuerPrivateKey: CryptoKey;
    readonly subjectPublicKey: CryptoKey;
}
/**
 * @deprecated Use {Certificate.issue} instead
 */
export declare function generateStubCert(config?: Partial<StubCertConfig>): Promise<Certificate>;
export declare function calculateDigestHex(algorithm: string, plaintext: ArrayBuffer | Buffer): string;
export declare function sha256Hex(plaintext: ArrayBuffer | Buffer): string;
export declare function mockSpy<T, Y extends any[]>(spy: jest.MockInstance<T, Y>, mockImplementation?: () => any): jest.MockInstance<T, Y>;
export declare function getPromiseRejection<ErrorType extends Error>(promise: Promise<any>): Promise<ErrorType>;
export declare function catchError<ErrorType extends Error>(func: () => void, errorClass: new () => ErrorType): ErrorType;
/**
 * Assert that two `ArrayBuffer`s are equivalent.
 *
 * expect(value1).toEqual(value2) does NOT work with ArrayBuffer instances: It always passes.
 *
 * @param expectedBuffer
 * @param actualBuffer
 */
export declare function expectArrayBuffersToEqual(expectedBuffer: ArrayBuffer, actualBuffer: ArrayBuffer): void;
export declare function getMockInstance(mockedObject: any): jest.MockInstance<any, any>;
export declare function getMockContext(mockedObject: any): jest.MockContext<any, any>;
export declare function reSerializeCertificate(cert: Certificate): Certificate;
export declare function arrayBufferFrom(input: any): ArrayBuffer;
export declare function arrayToAsyncIterable<T>(array: readonly T[]): AsyncIterable<T>;
export declare function asyncIterableToArray<T>(iterable: AsyncIterable<T>): Promise<readonly T[]>;
export declare function getAsn1SequenceItem(fields: asn1js.Sequence | asn1js.BaseBlock<any>, itemIndex: number): asn1js.Primitive;
export {};
