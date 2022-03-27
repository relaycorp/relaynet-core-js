import { fromBER, BaseBlock } from 'asn1js';
import * as pkijs from 'pkijs';

export function getPkijsCrypto(): SubtleCrypto {
  const cryptoEngine = pkijs.getCrypto();
  if (cryptoEngine === undefined) {
    throw new Error('PKI.js crypto engine is undefined');
  }
  return cryptoEngine;
}

export function derDeserialize(derValue: ArrayBuffer): BaseBlock<any> {
  const asn1Value = fromBER(derValue);
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
