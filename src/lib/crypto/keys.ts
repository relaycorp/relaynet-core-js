import bufferToArray from 'buffer-to-arraybuffer';
import { getAlgorithmParameters } from 'pkijs';

import { getPkijsCrypto } from './_utils';
import { ECDHCurveName, HashingAlgorithm, RSAModulus } from './algorithms';
import { PrivateKey } from './PrivateKey';

const cryptoEngine = getPkijsCrypto();

const DEFAULT_RSA_KEY_PARAMS: RsaHashedImportParams = {
  hash: { name: 'SHA-256' },
  name: 'RSA-PSS',
};

//region Key generators

export interface RSAKeyGenOptions {
  readonly modulus: RSAModulus;
  readonly hashingAlgorithm: HashingAlgorithm;
}

/**
 * Generate an RSA-PSS key pair.
 *
 * @param options The RSA key generation options
 * @throws Error If the modulus or the hashing algorithm is disallowed by RS-018.
 */
export async function generateRSAKeyPair(
  options: Partial<RSAKeyGenOptions> = {},
): Promise<CryptoKeyPair> {
  const modulus = options.modulus ?? 2048;
  if (modulus < 2048) {
    throw new Error(`RSA modulus must be => 2048 per RS-018 (got ${modulus})`);
  }

  const hashingAlgorithm = options.hashingAlgorithm ?? 'SHA-256';
  // RS-018 disallows MD5 and SHA-1, but only SHA-1 is supported in WebCrypto
  if ((hashingAlgorithm as any) === 'SHA-1') {
    throw new Error('SHA-1 is disallowed by RS-018');
  }

  const algorithm = getAlgorithmParameters('RSA-PSS', 'generateKey');
  const rsaAlgorithm = algorithm.algorithm as RsaHashedKeyAlgorithm;
  // tslint:disable-next-line:no-object-mutation
  rsaAlgorithm.hash.name = hashingAlgorithm;
  // tslint:disable-next-line:no-object-mutation
  rsaAlgorithm.modulusLength = modulus;

  return cryptoEngine.generateKey(rsaAlgorithm, true, algorithm.usages);
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

export async function getRSAPublicKeyFromPrivate(privateKey: CryptoKey): Promise<CryptoKey> {
  const publicKeyDer = bufferToArray(await derSerializePublicKey(privateKey));
  return cryptoEngine.importKey('spki', publicKeyDer, privateKey.algorithm, true, ['verify']);
}

//endregion

//region Key serialization

/**
 * Return DER serialization of public key.
 *
 * @param publicKey
 */
export async function derSerializePublicKey(publicKey: CryptoKey): Promise<Buffer> {
  const publicKeyDer =
    publicKey instanceof PrivateKey
      ? ((await publicKey.provider.exportKey('spki', publicKey)) as ArrayBuffer)
      : await cryptoEngine.exportKey('spki', publicKey);
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
  publicKeyDer: Buffer | ArrayBuffer,
  curveName: NamedCurve = 'P-256',
): Promise<CryptoKey> {
  const keyData = publicKeyDer instanceof Buffer ? bufferToArray(publicKeyDer) : publicKeyDer;
  return cryptoEngine.importKey('spki', keyData, { name: 'ECDH', namedCurve: curveName }, true, []);
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
  const publicKeyDer = await derSerializePublicKey(publicKey);
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

export async function getIdFromIdentityKey(identityPublicKey: CryptoKey): Promise<string> {
  const algorithmName = identityPublicKey.algorithm.name;
  if (!algorithmName.startsWith('RSA-')) {
    throw new Error(`Only RSA keys are supported (got ${algorithmName})`);
  }
  const keyDigest = await getPublicKeyDigestHex(identityPublicKey);
  return `0${keyDigest}`;
}
