import { Constructed, OctetString, Repeated, verifySchema } from 'asn1js';

import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../../asn1';
import InvalidMessageError from '../../messages/InvalidMessageError';

export class HandshakeResponse {
  public static deserialize(serialization: ArrayBuffer): HandshakeResponse {
    const result = verifySchema(serialization, HandshakeResponse.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Handshake response is malformed');
    }

    const responseASN1 = result.result.HandshakeResponse;
    const signatures = responseASN1.nonceSignatures.valueBlock.value.map(
      (s: OctetString) => s.valueBlock.valueHex,
    );
    return new HandshakeResponse(signatures);
  }

  private static readonly SCHEMA = makeHeterogeneousSequenceSchema('HandshakeResponse', [
    new Constructed({
      name: 'nonceSignatures',
      value: new Repeated({
        name: 'nonceSignature',
        value: new OctetString({ name: 'signature' } as any),
      } as any),
    } as any),
  ]);

  constructor(public nonceSignatures: readonly ArrayBuffer[]) {}

  public serialize(): ArrayBuffer {
    const asn1NonceSignatures = this.nonceSignatures.map((s) => new OctetString({ valueHex: s }));
    const nonceSignaturesASN1 = new Constructed({ value: asn1NonceSignatures } as any);
    return makeImplicitlyTaggedSequence(nonceSignaturesASN1).toBER();
  }
}
