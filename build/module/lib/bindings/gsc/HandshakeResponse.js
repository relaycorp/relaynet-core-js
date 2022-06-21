import { Constructed, OctetString, Repeated, verifySchema } from 'asn1js';
import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../../asn1';
import InvalidMessageError from '../../messages/InvalidMessageError';
export class HandshakeResponse {
    nonceSignatures;
    static deserialize(serialization) {
        const result = verifySchema(serialization, HandshakeResponse.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError('Handshake response is malformed');
        }
        const responseASN1 = result.result.HandshakeResponse;
        const signatures = responseASN1.nonceSignatures.valueBlock.value.map((s) => s.valueBlock.valueHex);
        return new HandshakeResponse(signatures);
    }
    static SCHEMA = makeHeterogeneousSequenceSchema('HandshakeResponse', [
        new Constructed({
            name: 'nonceSignatures',
            value: new Repeated({
                name: 'nonceSignature',
                value: new OctetString({ name: 'signature' }),
            }),
        }),
    ]);
    constructor(nonceSignatures) {
        this.nonceSignatures = nonceSignatures;
    }
    serialize() {
        const asn1NonceSignatures = this.nonceSignatures.map((s) => new OctetString({ valueHex: s }));
        const nonceSignaturesASN1 = new Constructed({ value: asn1NonceSignatures });
        return makeImplicitlyTaggedSequence(nonceSignaturesASN1).toBER();
    }
}
//# sourceMappingURL=HandshakeResponse.js.map