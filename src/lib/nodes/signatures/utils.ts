import { ObjectIdentifier, OctetString } from 'asn1js';

import { makeImplicitlyTaggedSequence } from '../../asn1';

export function makeSafePlaintext(plaintext: ArrayBuffer, oid: string): ArrayBuffer {
  return makeImplicitlyTaggedSequence(
    new ObjectIdentifier({ value: oid }),
    new OctetString({ valueHex: plaintext }),
  ).toBER();
}
