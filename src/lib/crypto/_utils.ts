import * as asn1js from 'asn1js';

import { NODE_ENGINE } from './pkijs';

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
  NODE_ENGINE.getRandomValues(new Uint8Array(value));
  return value;
}
