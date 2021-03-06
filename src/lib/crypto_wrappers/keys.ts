import bufferToArray from 'buffer-to-arraybuffer';
import { getAlgorithmParameters } from 'pkijs';

import { getPkijsCrypto } from './_utils';

const cryptoEngine = getPkijsCrypto();

export type ECDHCurveName = 'P-256' | 'P-384' | 'P-521';

const DEFAULT_RSA_KEY_PARAMS: RsaHashedImportParams = {
  hash: { name: 'SHA-256' },
  name: 'RSA-PSS',
};

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

  const keyPair = await cryptoEngine.generateKey(
    algorithm.algorithm,
    true,
    // tslint:disable-next-line:readonly-array
    algorithm.usages as KeyUsage[],
  );
  return keyPair as CryptoKeyPair;
}

/**
 * Generate ECDH key pair.
 *
 * @param curveName
 */
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

/**
 * Return DER serialization of public key.
 *
 * @param publicKey
 */
export async function derSerializePublicKey(publicKey: CryptoKey): Promise<Buffer> {
  const publicKeyDer = await cryptoEngine.exportKey('spki', publicKey);
  return Buffer.from(publicKeyDer);
}

/**
 * Return DER serialization of private key.
 *
 * @param privateKey
 */
export async function derSerializePrivateKey(privateKey: CryptoKey): Promise<Buffer> {
  const keyDer = (await cryptoEngine.exportKey('pkcs8', privateKey)) as ArrayBuffer;
  return Buffer.from(keyDer);
}

//endregion

//region key deserialization

/**
 * Parse DER-serialized RSA public key.
 *
 * @param publicKeyDer
 * @param algorithmOptions
 */
export async function derDeserializeRSAPublicKey(
  publicKeyDer: Buffer | ArrayBuffer,
  algorithmOptions: RsaHashedImportParams = DEFAULT_RSA_KEY_PARAMS,
): Promise<CryptoKey> {
  const keyData = publicKeyDer instanceof Buffer ? bufferToArray(publicKeyDer) : publicKeyDer;
  return cryptoEngine.importKey('spki', keyData, algorithmOptions, true, ['verify']);
}

/**
 * Parse DER-serialized ECDH public key.
 *
 * @param publicKeyDer
 * @param curveName
 */
export async function derDeserializeECDHPublicKey(
  publicKeyDer: Buffer,
  curveName: NamedCurve = 'P-256',
): Promise<CryptoKey> {
  return cryptoEngine.importKey(
    'spki',
    bufferToArray(publicKeyDer),
    { name: 'ECDH', namedCurve: curveName },
    true,
    [],
  );
}

/**
 * Parse DER-serialized RSA private key.
 *
 * @param privateKeyDer
 * @param algorithmOptions
 */
export async function derDeserializeRSAPrivateKey(
  privateKeyDer: Buffer,
  algorithmOptions: RsaHashedImportParams = DEFAULT_RSA_KEY_PARAMS,
): Promise<CryptoKey> {
  return cryptoEngine.importKey('pkcs8', bufferToArray(privateKeyDer), algorithmOptions, true, [
    'sign',
  ]);
}

/**
 * Parse DER-serialized ECDH private key.
 *
 * @param privateKeyDer
 * @param curveName
 */
export async function derDeserializeECDHPrivateKey(
  privateKeyDer: Buffer,
  curveName: NamedCurve = 'P-256',
): Promise<CryptoKey> {
  return cryptoEngine.importKey(
    'pkcs8',
    bufferToArray(privateKeyDer),
    { name: 'ECDH', namedCurve: curveName },
    true,
    ['deriveBits', 'deriveKey'],
  );
}

//endregion

/**
 * Return SHA-256 digest of public key.
 *
 * @param publicKey
 */
export async function getPublicKeyDigest(publicKey: CryptoKey): Promise<ArrayBuffer> {
  const publicKeyDer = await cryptoEngine.exportKey('spki', publicKey);
  return cryptoEngine.digest({ name: 'SHA-256' }, publicKeyDer);
}

/**
 * Return hexadecimal, SHA-256 digest of public key.
 *
 * @param publicKey
 */
export async function getPublicKeyDigestHex(publicKey: CryptoKey): Promise<string> {
  const digest = Buffer.from(await getPublicKeyDigest(publicKey));
  return digest.toString('hex');
}
