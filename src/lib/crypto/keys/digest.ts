import { derSerializePublicKey } from './serialisation';
import { NODE_ENGINE } from '../pkijs';

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
