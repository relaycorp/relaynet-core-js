/**
 * Plain RSA signatures are used when CMS SignedData can't be used. That is, when the signer
 * doesn't (yet) have a certificate.
 */

import { getEngineForKey } from './pkijs';

const rsaPssParams = {
  hash: { name: 'SHA-256' },
  name: 'RSA-PSS',
  saltLength: 32,
};

export async function sign(plaintext: ArrayBuffer, privateKey: CryptoKey): Promise<ArrayBuffer> {
  const engine = getEngineForKey(privateKey);
  return engine.sign(rsaPssParams, privateKey, plaintext);
}

export async function verify(
  signature: ArrayBuffer,
  publicKey: CryptoKey,
  expectedPlaintext: ArrayBuffer,
): Promise<boolean> {
  const engine = getEngineForKey(publicKey);
  return engine.verify(rsaPssParams, publicKey, signature, expectedPlaintext);
}
