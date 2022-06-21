import { ObjectIdentifier, OctetString, Primitive, verifySchema } from 'asn1js';
import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../../asn1';
import { derDeserializeRSAPublicKey, derSerializePublicKey } from '../../crypto_wrappers/keys';
import { sign, verify } from '../../crypto_wrappers/rsaSigning';
import InvalidMessageError from '../../messages/InvalidMessageError';
import { RELAYNET_OIDS } from '../../oids';
export class PrivateNodeRegistrationRequest {
    privateNodePublicKey;
    pnraSerialized;
    static async deserialize(serialization) {
        const result = verifySchema(serialization, PrivateNodeRegistrationRequest.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError('Serialization is not a valid PrivateNodeRegistrationRequest');
        }
        const request = result.result.PrivateNodeRegistrationRequest;
        let privateNodePublicKey;
        try {
            privateNodePublicKey = await derDeserializeRSAPublicKey(request.privateNodePublicKey.valueBlock.valueHex);
        }
        catch (err) {
            throw new InvalidMessageError('Private node public key is not valid', err);
        }
        const authorizationSerializedASN1 = request.pnraSerialized;
        const countersignature = request.countersignature.valueBlock.valueHex;
        const countersignaturePlaintext = PrivateNodeRegistrationRequest.makePNRACountersignaturePlaintext(authorizationSerializedASN1);
        if (!(await verify(countersignature, privateNodePublicKey, countersignaturePlaintext))) {
            throw new InvalidMessageError('Authorization countersignature is invalid');
        }
        return new PrivateNodeRegistrationRequest(privateNodePublicKey, authorizationSerializedASN1.valueBlock.valueHex);
    }
    static SCHEMA = makeHeterogeneousSequenceSchema('PrivateNodeRegistrationRequest', [
        new Primitive({ name: 'privateNodePublicKey' }),
        new Primitive({ name: 'pnraSerialized' }),
        new Primitive({ name: 'countersignature' }),
    ]);
    static makePNRACountersignaturePlaintext(pnraSerializedASN1) {
        return makeImplicitlyTaggedSequence(new ObjectIdentifier({
            value: RELAYNET_OIDS.NODE_REGISTRATION.AUTHORIZATION_COUNTERSIGNATURE,
        }), pnraSerializedASN1).toBER();
    }
    constructor(privateNodePublicKey, pnraSerialized) {
        this.privateNodePublicKey = privateNodePublicKey;
        this.pnraSerialized = pnraSerialized;
    }
    async serialize(privateNodePrivateKey) {
        const privateNodePublicKeySerialized = await derSerializePublicKey(this.privateNodePublicKey);
        const authorizationSerializedASN1 = new OctetString({ valueHex: this.pnraSerialized });
        const countersignaturePlaintext = PrivateNodeRegistrationRequest.makePNRACountersignaturePlaintext(authorizationSerializedASN1);
        const signature = await sign(countersignaturePlaintext, privateNodePrivateKey);
        return makeImplicitlyTaggedSequence(new OctetString({ valueHex: privateNodePublicKeySerialized }), authorizationSerializedASN1, new OctetString({ valueHex: signature })).toBER();
    }
}
//# sourceMappingURL=PrivateNodeRegistrationRequest.js.map