import { OctetString, Primitive, verifySchema } from 'asn1js';
import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../../asn1';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import InvalidMessageError from '../InvalidMessageError';
export class CargoCollectionRequest {
    cargoDeliveryAuthorization;
    static deserialize(serialization) {
        const result = verifySchema(serialization, CargoCollectionRequest.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError('Serialization is not a valid CargoCollectionRequest');
        }
        const requestASN1 = result.result.CargoCollectionRequest;
        const cdaSerialized = requestASN1.cda.valueBlock.valueHex;
        let cda;
        try {
            cda = Certificate.deserialize(cdaSerialized);
        }
        catch (error) {
            throw new InvalidMessageError(error, 'CargoCollectionRequest contains a malformed Cargo Delivery Authorization');
        }
        return new CargoCollectionRequest(cda);
    }
    static SCHEMA = makeHeterogeneousSequenceSchema('CargoCollectionRequest', [
        new Primitive({ name: 'cda' }),
    ]);
    constructor(cargoDeliveryAuthorization) {
        this.cargoDeliveryAuthorization = cargoDeliveryAuthorization;
    }
    serialize() {
        const cdaASN1 = new OctetString({ valueHex: this.cargoDeliveryAuthorization.serialize() });
        return makeImplicitlyTaggedSequence(cdaASN1).toBER();
    }
}
//# sourceMappingURL=CargoCollectionRequest.js.map