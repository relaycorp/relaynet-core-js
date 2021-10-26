import { OctetString, Primitive, verifySchema } from 'asn1js';

import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../../asn1';
import InvalidMessageError from '../../messages/InvalidMessageError';

export class HandshakeChallenge {
  public static deserialize(serialization: ArrayBuffer): HandshakeChallenge {
    const result = verifySchema(serialization, HandshakeChallenge.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Handshake challenge is malformed');
    }

    const challengeASN1 = result.result.HandshakeChallenge;
    const nonce = challengeASN1.nonce.valueBlock.valueHex;
    return new HandshakeChallenge(nonce);
  }

  private static readonly SCHEMA = makeHeterogeneousSequenceSchema('HandshakeChallenge', [
    new Primitive({ name: 'nonce' }),
  ]);

  constructor(public nonce: ArrayBuffer) {}

  public serialize(): ArrayBuffer {
    return makeImplicitlyTaggedSequence(new OctetString({ valueHex: this.nonce })).toBER();
  }
}
