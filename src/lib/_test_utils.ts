import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import { createHash } from 'crypto';
import * as pkijs from 'pkijs';

import { generateRSAKeyPair, getPublicKeyDigestHex } from './crypto_wrappers/keys';
import Certificate from './crypto_wrappers/x509/Certificate';
import FullCertificateIssuanceOptions from './crypto_wrappers/x509/FullCertificateIssuanceOptions';

type PkijsValueType = pkijs.RelativeDistinguishedNames | pkijs.Certificate;

export function expectPkijsValuesToBeEqual(
  expectedValue: PkijsValueType,
  actualValue: PkijsValueType,
): void {
  expectAsn1ValuesToBeEqual(expectedValue.toSchema(), actualValue.toSchema());
}

type Asn1jsToBER = (sizeOnly?: boolean) => ArrayBuffer;

interface Asn1jsSerializable {
  readonly toBER: Asn1jsToBER;
}

export function expectAsn1ValuesToBeEqual(
  expectedValue: Asn1jsSerializable,
  actualValue: Asn1jsSerializable,
): void {
  expectBuffersToEqual(expectedValue.toBER(false), actualValue.toBER(false));
}

interface StubCertConfig {
  readonly attributes: Partial<FullCertificateIssuanceOptions>;
  readonly issuerCertificate: Certificate;
  readonly issuerPrivateKey: CryptoKey;
  readonly subjectPublicKey: CryptoKey;
}

export async function generateStubCert(config: Partial<StubCertConfig> = {}): Promise<Certificate> {
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

export function calculateDigestHex(algorithm: string, plaintext: ArrayBuffer | Buffer): string {
  return createHash(algorithm).update(Buffer.from(plaintext)).digest('hex');
}

export function sha256Hex(plaintext: ArrayBuffer | Buffer): string {
  return calculateDigestHex('sha256', plaintext);
}

// tslint:disable-next-line:readonly-array
export function mockSpy<T, Y extends any[]>(
  spy: jest.MockInstance<T, Y>,
  mockImplementation?: () => any,
): jest.MockInstance<T, Y> {
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

export async function getPromiseRejection<ErrorType extends Error>(
  promise: Promise<any>,
): Promise<ErrorType> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('Expected promise to throw');
}

/**
 * Assert that two buffers are of the same type and contain the same octets.
 *
 * expect(value1).toEqual(value2) does NOT work with ArrayBuffer instances: It always passes.
 *
 * @param expectedBuffer
 * @param actualBuffer
 */
export function expectBuffersToEqual(
  expectedBuffer: Buffer | ArrayBuffer,
  actualBuffer: Buffer | ArrayBuffer,
): void {
  expect(expectedBuffer.byteLength).toEqual(actualBuffer.byteLength);
  if (expectedBuffer instanceof Buffer) {
    expect(actualBuffer).toBeInstanceOf(Buffer);
    expect(expectedBuffer.equals(actualBuffer as Buffer)).toBeTrue();
  } else {
    expect(expectedBuffer).toBeInstanceOf(ArrayBuffer);
    expect(actualBuffer).toBeInstanceOf(ArrayBuffer);

    const actualBuffer1 = Buffer.from(expectedBuffer);
    const actualBuffer2 = Buffer.from(actualBuffer);
    expect(actualBuffer1.equals(actualBuffer2)).toBeTrue();
  }
}

export function getMockContext(mockedObject: any): jest.MockContext<any, any> {
  const mockInstance = (mockedObject as unknown) as jest.MockInstance<any, any>;
  return mockInstance.mock;
}

export function reSerializeCertificate(cert: Certificate): Certificate {
  // TODO: Raise bug in PKI.js project
  // PKI.js sometimes tries to use attributes that are only set *after* the certificate has been
  // deserialized, so you'd get a TypeError if you use a certificate you just created in memory.
  // For example, `extension.parsedValue` would be `undefined` in
  // https://github.com/PeculiarVentures/PKI.js/blob/9a39551aa9f1445406f96680318014c8d714e8e3/src/CertificateChainValidationEngine.js#L155
  return Certificate.deserialize(cert.serialize());
}

export function arrayBufferFrom(input: any): ArrayBuffer {
  return bufferToArray(Buffer.from(input));
}

export async function* arrayToAsyncIterable<T>(array: readonly T[]): AsyncIterable<T> {
  for (const item of array) {
    yield item;
  }
}

export async function asyncIterableToArray<T>(iterable: AsyncIterable<T>): Promise<readonly T[]> {
  // tslint:disable-next-line:readonly-array
  const values = [];
  for await (const value of iterable) {
    values.push(value);
  }
  return values;
}

export function getAsn1SequenceItem(
  fields: asn1js.Sequence | asn1js.LocalBaseBlock,
  itemIndex: number,
): asn1js.Primitive {
  expect(fields).toBeInstanceOf(asn1js.Sequence);
  const itemBlock = (fields as asn1js.Sequence).valueBlock.value[itemIndex] as asn1js.Primitive;
  expect(itemBlock).toBeInstanceOf(asn1js.Primitive);
  expect(itemBlock.idBlock.tagClass).toEqual(3); // Context-specific
  expect(itemBlock.idBlock.tagNumber).toEqual(itemIndex);
  return itemBlock as any;
}
