import { ObjectIdentifier, OctetString } from 'asn1js';
import { makeImplicitlyTaggedSequence } from '../../asn1';
export function makeSafePlaintext(plaintext, oid) {
    return makeImplicitlyTaggedSequence(new ObjectIdentifier({ value: oid }), new OctetString({ valueHex: plaintext })).toBER();
}
//# sourceMappingURL=utils.js.map