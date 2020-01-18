import bufferToArray from 'buffer-to-arraybuffer';
import { getAlgorithmParameters } from 'pkijs';

import { getPkijsCrypto } from './_utils';

const cryptoEngine = getPkijsCrypto();

export type ECDHCurveName = 'P-256' | 'P-384' | 'P-521';

//region Key generators

/**
 * Generate an RSA key pair
 *
 * @param modulus The RSA modulus for the keys (2048 or greater).
 * @param hashingAlgorithm The hashing algorithm (e.g., SHA-256, SHA-384, SHA-512).
 * @throws Error If the modulus or the hashing algorithm is disallowed by RS-018.
 */
export async function generateRSAKeyPair({
  modulus = 2048,
  hashingAlgorithm = 'SHA-256',
} = {}): Promise<CryptoKeyPair> {
  if (modulus < 2048) {
    throw new Error(`RSA modulus must be => 2048 per RS-018 (got ${modulus})`);
  }

  // RS-018 disallows MD5 and SHA-1, but only SHA-1 is supported in WebCrypto
  if (hashingAlgorithm === 'SHA-1') {
    throw new Error('SHA-1 is disallowed by RS-018');
  }

  const algorithm = getAlgorithmParameters('RSA-PSS', 'generatekey');
  // tslint:disable-next-line:no-object-mutation
  (algorithm.algorithm.hash as Algorithm).name = hashingAlgorithm;
  // tslint:disable-next-line:no-object-mutation
  algorithm.algorithm.modulusLength = modulus;

  return cryptoEngine.generateKey(algorithm.algorithm, true, algorithm.usages);
}

export async function generateECDHKeyPair(
  curveName: ECDHCurveName = 'P-256',
): Promise<CryptoKeyPair> {
  return cryptoEngine.generateKey({ name: 'ECDH', namedCurve: curveName }, true, [
    'deriveBits',
    'deriveKey',
  ]);
}

//endregion

//region Key serialization

export async function derSerializePublicKey(publicKey: CryptoKey): Promise<Buffer> {
  const publicKeyDer = await cryptoEngine.exportKey('spki', publicKey);
  return Buffer.from(publicKeyDer);
}

export async function derSerializePrivateKey(privateKey: CryptoKey): Promise<Buffer> {
  const keyDer = (await cryptoEngine.exportKey('pkcs8', privateKey)) as ArrayBuffer;
  return Buffer.from(keyDer);
}

//endregion

//region key deserialization

export async function derDeserializeRSAPublicKey(
  publicKeyDer: Buffer,
  algorithmOptions: RsaHashedImportParams,
): Promise<CryptoKey> {
  return cryptoEngine.importKey('spki', bufferToArray(publicKeyDer), algorithmOptions, true, [
    'verify',
  ]);
}

export async function derDeserializeECDHPublicKey(
  publicKeyDer: Buffer,
  algorithmOptions: EcKeyImportParams,
): Promise<CryptoKey> {
  return cryptoEngine.importKey('spki', bufferToArray(publicKeyDer), algorithmOptions, true, []);
}

export async function derDeserializeRSAPrivateKey(
  privateKeyDer: Buffer,
  algorithmOptions: RsaHashedImportParams,
): Promise<CryptoKey> {
  return cryptoEngine.importKey('pkcs8', bufferToArray(privateKeyDer), algorithmOptions, true, [
    'sign',
  ]);
}

export async function derDeserializeECDHPrivateKey(
  privateKeyDer: Buffer,
  algorithmOptions: EcKeyImportParams,
): Promise<CryptoKey> {
  return cryptoEngine.importKey('pkcs8', bufferToArray(privateKeyDer), algorithmOptions, true, [
    'deriveBits',
    'deriveKey',
  ]);
}

//endregion
