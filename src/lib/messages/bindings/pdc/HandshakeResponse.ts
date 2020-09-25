import { OctetString } from 'asn1js';

import { derSerializeHomogeneousSequence } from '../../../asn1';

export class HandshakeResponse {
  constructor(public nonceSignatures: readonly ArrayBuffer[]) {}

  public serialize(): ArrayBuffer {
    const items = this.nonceSignatures.map((s) => new OctetString({ valueHex: s }));
    return derSerializeHomogeneousSequence(items);
  }
}
