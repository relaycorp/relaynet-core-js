import { createHash } from 'crypto';
import * as pkijs from 'pkijs';
import { generateRsaKeyPair } from './crypto';
import Certificate from './pki/Certificate';
import CertificateOptions from './pki/CertificateOptions';

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
  expect(sha256Hex(expectedValue.toBER(false))).toEqual(sha256Hex(actualValue.toBER(false)));
}

interface StubCertConfig {
  readonly attributes: Partial<CertificateOptions>;
  readonly issuerCertificate: Certificate;
  readonly issuerPrivateKey: CryptoKey;
  readonly subjectPublicKey: CryptoKey;
}

export async function generateStubCert(config: Partial<StubCertConfig> = {}): Promise<Certificate> {
  const keyPair = await generateRsaKeyPair();
  const futureDate = new Date();
  futureDate.setDate(futureDate.getDate() + 1);
  return Certificate.issue(
    config.issuerPrivateKey || keyPair.privateKey,
    {
      serialNumber: 1,
      subjectPublicKey: config.subjectPublicKey || keyPair.publicKey,
      validityEndDate: futureDate,
      ...config.attributes,
    },
    config.issuerCertificate,
  );
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
