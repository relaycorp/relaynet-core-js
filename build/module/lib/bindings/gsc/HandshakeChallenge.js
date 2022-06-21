import { OctetString, Primitive, verifySchema } from 'asn1js';
import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../../asn1';
import InvalidMessageError from '../../messages/InvalidMessageError';
export class HandshakeChallenge {
    nonce;
    static deserialize(serialization) {
        const result = verifySchema(serialization, HandshakeChallenge.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError('Handshake challenge is malformed');
        }
        const challengeASN1 = result.result.HandshakeChallenge;
        const nonce = challengeASN1.nonce.valueBlock.valueHex;
        return new HandshakeChallenge(nonce);
    }
    static SCHEMA = makeHeterogeneousSequenceSchema('HandshakeChallenge', [
        new Primitive({ name: 'nonce' }),
    ]);
    constructor(nonce) {
        this.nonce = nonce;
    }
    serialize() {
        return makeImplicitlyTaggedSequence(new OctetString({ valueHex: this.nonce })).toBER();
    }
}
//# sourceMappingURL=HandshakeChallenge.js.map