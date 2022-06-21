import { ObjectIdentifier, OctetString, Primitive, verifySchema } from 'asn1js';
import { asn1DateTimeToDate, dateToASN1DateTimeInUTC, makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence, } from '../../asn1';
import { sign, verify } from '../../crypto_wrappers/rsaSigning';
import InvalidMessageError from '../../messages/InvalidMessageError';
import { RELAYNET_OIDS } from '../../oids';
export class PrivateNodeRegistrationAuthorization {
    expiryDate;
    gatewayData;
    static async deserialize(serialization, gatewayPublicKey) {
        const result = verifySchema(serialization, PrivateNodeRegistrationAuthorization.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError('Serialization is not a valid PrivateNodeRegistrationAuthorization');
        }
        const authorizationASN1 = result.result.PrivateNodeRegistrationAuthorization;
        const expiryDate = asn1DateTimeToDate(authorizationASN1.expiryDate);
        if (expiryDate < new Date()) {
            throw new InvalidMessageError('Authorization already expired');
        }
        const expectedSignaturePlaintext = PrivateNodeRegistrationAuthorization.makeSignaturePlaintext(authorizationASN1.expiryDate, authorizationASN1.gatewayData);
        const isSignatureValid = await verify(authorizationASN1.signature.valueBlock.valueHex, gatewayPublicKey, expectedSignaturePlaintext);
        if (!isSignatureValid) {
            throw new InvalidMessageError('Authorization signature is invalid');
        }
        const gatewayData = authorizationASN1.gatewayData.valueBlock.valueHex;
        return new PrivateNodeRegistrationAuthorization(expiryDate, gatewayData);
    }
    static SCHEMA = makeHeterogeneousSequenceSchema('PrivateNodeRegistrationAuthorization', [
        new Primitive({ name: 'expiryDate' }),
        new Primitive({ name: 'gatewayData' }),
        new Primitive({ name: 'signature' }),
    ]);
    static makeSignaturePlaintext(expiryDateASN1, gatewayDataASN1) {
        return makeImplicitlyTaggedSequence(new ObjectIdentifier({ value: RELAYNET_OIDS.NODE_REGISTRATION.AUTHORIZATION }), expiryDateASN1, gatewayDataASN1).toBER();
    }
    constructor(expiryDate, gatewayData) {
        this.expiryDate = expiryDate;
        this.gatewayData = gatewayData;
    }
    async serialize(gatewayPrivateKey) {
        const expiryDateASN1 = dateToASN1DateTimeInUTC(this.expiryDate);
        const gatewayDataASN1 = new OctetString({ valueHex: this.gatewayData });
        const signaturePlaintext = PrivateNodeRegistrationAuthorization.makeSignaturePlaintext(expiryDateASN1, gatewayDataASN1);
        const signature = await sign(signaturePlaintext, gatewayPrivateKey);
        return makeImplicitlyTaggedSequence(expiryDateASN1, gatewayDataASN1, new OctetString({ valueHex: signature })).toBER();
    }
}
//# sourceMappingURL=PrivateNodeRegistrationAuthorization.js.map