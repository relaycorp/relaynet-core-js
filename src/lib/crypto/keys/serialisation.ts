import bufferToArray from 'buffer-to-arraybuffer';

import { NODE_ENGINE } from '../pkijs';
import { CryptoKeyWithProvider } from './CryptoKeyWithProvider';

const DEFAULT_RSA_KEY_PARAMS: RsaHashedImportParams = {
  hash: { name: 'SHA-256' },
  name: 'RSA-PSS',
};

/**
 * Return DER serialization of public key.
 *
 * @param publicKey
 */
export async function derSerializePublicKey(
  publicKey: CryptoKey | CryptoKeyWithProvider,
): Promise<Buffer> {
  let publicKeyDer: ArrayBuffer;
  if ((publicKey as CryptoKeyWithProvider).provider) {
    // This is likely a KMS-backed private key, so use the provider directly to prevent the
    // engine from exporting the key to JWK first.
    // https://github.com/relaycorp/cloud-gateway/issues/93
    const provider = (publicKey as CryptoKeyWithProvider).provider;
    publicKeyDer = (await provider.exportKey('spki', publicKey as CryptoKey)) as ArrayBuffer;
  } else {
    publicKeyDer = await NODE_ENGINE.exportKey('spki', publicKey as CryptoKey);
  }
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
