import bufferToArray from 'buffer-to-arraybuffer';

import { PrivateKey } from './PrivateKey';
import { NODE_ENGINE } from '../pkijs';

const DEFAULT_RSA_KEY_PARAMS: RsaHashedImportParams = {
  hash: { name: 'SHA-256' },
  name: 'RSA-PSS',
};

/**
 * Return DER serialization of public key.
 *
 * @param publicKey
 */
export async function derSerializePublicKey(publicKey: CryptoKey): Promise<Buffer> {
  const publicKeyDer =
    publicKey instanceof PrivateKey
      ? ((await publicKey.provider.exportKey('spki', publicKey)) as ArrayBuffer)
      : await NODE_ENGINE.exportKey('spki', publicKey);
  return Buffer.from(publicKeyDer);
}

/**
 * Return DER serialization of private key.
 *
 * @param privateKey
 */
export async function derSerializePrivateKey(privateKey: CryptoKey): Promise<Buffer> {
  const keyDer = (await NODE_ENGINE.exportKey('pkcs8', privateKey)) as ArrayBuffer;
  return Buffer.from(keyDer);
}

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
  return NODE_ENGINE.importKey('spki', keyData, algorithmOptions, true, ['verify']);
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
  const algorithm: AlgorithmIdentifier = { name: 'ECDH', namedCurve: curveName } as any;
  return NODE_ENGINE.importKey('spki', keyData, algorithm, true, []);
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
  return NODE_ENGINE.importKey('pkcs8', bufferToArray(privateKeyDer), algorithmOptions, true, [
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
  const algorithm: AlgorithmIdentifier = { name: 'ECDH', namedCurve: curveName } as any;
  return NODE_ENGINE.importKey('pkcs8', bufferToArray(privateKeyDer), algorithm, true, [
    'deriveBits',
    'deriveKey',
  ]);
}
