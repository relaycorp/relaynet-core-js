import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

export function getPkijsCrypto(): SubtleCrypto {
  const cryptoEngine = pkijs.getCrypto();
  if (cryptoEngine === undefined) {
    throw new Error('PKI.js crypto engine is undefined');
  }
  return cryptoEngine;
}

export function deserializeDer(derValue: ArrayBuffer): asn1js.LocalBaseBlock {
  const asn1Value = asn1js.fromBER(derValue);
  if (asn1Value.offset === -1) {
    throw new Error('Value is not DER-encoded');
  }
  return asn1Value.result;
}

export async function getPublicKeyDigest(publicKey: CryptoKey): Promise<ArrayBuffer> {
  const pkijsCrypto = getPkijsCrypto();
  const publicKeyDer = await pkijsCrypto.exportKey('spki', publicKey);
  return pkijsCrypto.digest({ name: 'SHA-256' }, publicKeyDer);
}

export function generateRandom32BitUnsignedNumber(): number {
  const numberArray = new Uint32Array(4);
  // @ts-ignore
  getPkijsCrypto().getRandomValues(numberArray);
  const numberBuffer = Buffer.from(numberArray);
  return numberBuffer.readUInt32LE(0);
}
