import { OctetString, verifySchema } from 'asn1js';
import { derSerializeHeterogeneousSequence, makeSequenceSchema } from '../../../asn1';
import InvalidMessageError from '../../InvalidMessageError';

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

  private static readonly SCHEMA = makeSequenceSchema('HandshakeChallenge', ['nonce']);

  constructor(public nonce: ArrayBuffer) {}

  public serialize(): ArrayBuffer {
    return derSerializeHeterogeneousSequence(new OctetString({ valueHex: this.nonce }));
  }
}
