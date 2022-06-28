import * as asn1js from 'asn1js';
import { CryptoEngine, getCrypto } from 'pkijs';

import { PrivateKey } from './PrivateKey';

export function getPkijsCrypto(): SubtleCrypto {
  const cryptoEngine = getCrypto();
  if (!cryptoEngine) {
    throw new Error('PKI.js crypto engine is undefined');
  }
  return cryptoEngine;
}

export function getEngineFromPrivateKey(key: CryptoKey | PrivateKey): CryptoEngine | undefined {
  if (key instanceof PrivateKey) {
    return new CryptoEngine({ crypto: key.crypto });
  }
  return undefined;
}

export function derDeserialize(derValue: ArrayBuffer): asn1js.AsnType {
  const asn1Value = asn1js.fromBER(derValue);
  if (asn1Value.offset === -1) {
    throw new Error('Value is not DER-encoded');
  }
  return asn1Value.result;
}

export function generateRandom64BitValue(): ArrayBuffer {
  const value = new ArrayBuffer(8);
  // @ts-ignore
  getPkijsCrypto().getRandomValues(new Uint8Array(value));
  return value;
}
