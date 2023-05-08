/**
 * Plain RSA signatures are used when CMS SignedData can't be used. That is, when the signer
 * doesn't (yet) have a certificate.
 */

import { PrivateKey } from './keys/PrivateKey';
import { NODE_ENGINE } from './pkijs';

const rsaPssParams = {
  hash: { name: 'SHA-256' },
  name: 'RSA-PSS',
  saltLength: 32,
};

export async function sign(plaintext: ArrayBuffer, privateKey: CryptoKey): Promise<ArrayBuffer> {
  if (privateKey instanceof PrivateKey) {
    return privateKey.provider.sign(rsaPssParams, privateKey, plaintext);
  }
  return NODE_ENGINE.sign(rsaPssParams, privateKey, plaintext);
}

export async function verify(
  signature: ArrayBuffer,
  publicKey: CryptoKey,
  expectedPlaintext: ArrayBuffer,
): Promise<boolean> {
  return NODE_ENGINE.verify(rsaPssParams, publicKey, signature, expectedPlaintext);
}
