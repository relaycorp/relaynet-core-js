import { createHash } from 'crypto';
import * as pkijs from 'pkijs';

import { generateRSAKeyPair } from './crypto_wrappers/keys';
import Certificate from './crypto_wrappers/x509/Certificate';
import CertificateOptions from './crypto_wrappers/x509/CertificateOptions';

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
  readonly attributes: Partial<CertificateOptions>;
  readonly issuerCertificate: Certificate;
  readonly issuerPrivateKey: CryptoKey;
  readonly subjectPublicKey: CryptoKey;
}

export async function generateStubCert(config: Partial<StubCertConfig> = {}): Promise<Certificate> {
  const keyPair = await generateRSAKeyPair();
  const futureDate = new Date();
  futureDate.setDate(futureDate.getDate() + 1);
  return Certificate.issue({
    commonName: 'commonName',
    issuerCertificate: config.issuerCertificate,
    issuerPrivateKey: config.issuerPrivateKey || keyPair.privateKey,
    serialNumber: 1,
    subjectPublicKey: config.subjectPublicKey || keyPair.publicKey,
    validityEndDate: futureDate,
    ...config.attributes,
  });
}

export function sha256Hex(plaintext: ArrayBuffer): string {
  return createHash('sha256')
    .update(Buffer.from(plaintext))
    .digest('hex');
}

export async function expectPromiseToReject(
  promise: Promise<any>,
  expectedError: Error,
): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(expectedError.constructor);
    expect(error).toHaveProperty('message', expectedError.message);
    return;
  }
  throw new Error(`Expected promise to throw error ${expectedError}`);
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

export function expectBuffersToEqual(
  buffer1: Buffer | ArrayBuffer,
  buffer2: Buffer | ArrayBuffer,
): void {
  if (buffer1 instanceof Buffer) {
    expect(buffer2).toBeInstanceOf(Buffer);
    expect(buffer1.equals(buffer2 as Buffer)).toBeTrue();
  } else {
    expect(buffer1).toBeInstanceOf(ArrayBuffer);
    expect(buffer2).toBeInstanceOf(ArrayBuffer);

    const actualBuffer1 = Buffer.from(buffer1);
    const actualBuffer2 = Buffer.from(buffer2);
    expect(actualBuffer1.equals(actualBuffer2)).toBeTrue();
  }
}

export function getMockContext(mockedObject: any): jest.MockContext<any, any> {
  const mockInstance = (mockedObject as unknown) as jest.MockInstance<any, any>;
  return mockInstance.mock;
}
