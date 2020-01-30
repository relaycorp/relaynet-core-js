import { createHash } from 'crypto';
import * as pkijs from 'pkijs';

import { generateRSAKeyPair, getPublicKeyDigestHex } from './crypto_wrappers/keys';
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
  const subjectPublicKey = config.subjectPublicKey || keyPair.publicKey;
  return Certificate.issue({
    commonName: `0${getPublicKeyDigestHex(subjectPublicKey)}`,
    issuerCertificate: config.issuerCertificate,
    issuerPrivateKey: config.issuerPrivateKey || keyPair.privateKey,
    subjectPublicKey,
    validityEndDate: futureDate,
    ...config.attributes,
  });
}

export function sha256Hex(plaintext: ArrayBuffer | Buffer): string {
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

export function reSerializeCertificate(cert: Certificate): Certificate {
  // TODO: Raise bug in PKI.js project
  // PKI.js sometimes tries to use attributes that are only set *after* the certificate has been
  // deserialized, so you'd get a TypeError if you use a certificate you just created in memory.
  // For example, `extension.parsedValue` would be `undefined` in
  // https://github.com/PeculiarVentures/PKI.js/blob/9a39551aa9f1445406f96680318014c8d714e8e3/src/CertificateChainValidationEngine.js#L155
  return Certificate.deserialize(cert.serialize());
}
