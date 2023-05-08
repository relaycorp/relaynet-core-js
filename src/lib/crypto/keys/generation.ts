import bufferToArray from 'buffer-to-arraybuffer';
import { getAlgorithmParameters } from 'pkijs';

import { ECDHCurveName, HashingAlgorithm, RSAModulus } from '../algorithms';
import { NODE_ENGINE } from '../pkijs';
import { derSerializePublicKey } from './serialisation';

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

  return NODE_ENGINE.generateKey(rsaAlgorithm, true, algorithm.usages);
}

/**
 * Generate ECDH key pair.
 *
 * @param curveName
 */
export async function generateECDHKeyPair(
  curveName: ECDHCurveName = 'P-256',
): Promise<CryptoKeyPair> {
  return NODE_ENGINE.generateKey({ name: 'ECDH', namedCurve: curveName }, true, [
    'deriveBits',
    'deriveKey',
  ]);
}

export async function getRSAPublicKeyFromPrivate(privateKey: CryptoKey): Promise<CryptoKey> {
  const publicKeyDer = bufferToArray(await derSerializePublicKey(privateKey));
  return NODE_ENGINE.importKey('spki', publicKeyDer, privateKey.algorithm, true, ['verify']);
}

//endregion

//region Key serialization

//endregion

//region key deserialization

//endregion

/**
 * Return SHA-256 digest of public key.
 *
 * @param publicKey
 */
export async function getPublicKeyDigest(publicKey: CryptoKey): Promise<ArrayBuffer> {
  const publicKeyDer = await derSerializePublicKey(publicKey);
  return NODE_ENGINE.digest({ name: 'SHA-256' }, publicKeyDer);
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
