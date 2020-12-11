import { OctetString, Primitive, verifySchema } from 'asn1js';

import { derSerializeHeterogeneousSequence, makeHeterogeneousSequenceSchema } from '../../asn1';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import InvalidMessageError from '../InvalidMessageError';
import PayloadPlaintext from './PayloadPlaintext';

export class CargoCollectionRequest implements PayloadPlaintext {
  public static deserialize(serialization: ArrayBuffer): CargoCollectionRequest {
    const result = verifySchema(serialization, CargoCollectionRequest.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Serialization is not a valid CargoCollectionRequest');
    }

    const requestASN1 = result.result.CargoCollectionRequest;
    const cdaSerialized = requestASN1.cda.valueBlock.valueHex;
    let cda: Certificate;
    try {
      cda = Certificate.deserialize(cdaSerialized);
    } catch (error) {
      throw new InvalidMessageError(
        error,
        'CargoCollectionRequest contains a malformed Cargo Delivery Authorization',
      );
    }
    return new CargoCollectionRequest(cda);
  }

  private static readonly SCHEMA = makeHeterogeneousSequenceSchema('CargoCollectionRequest', [
    new Primitive({ name: 'cda' }),
  ]);

  constructor(readonly cargoDeliveryAuthorization: Certificate) {}

  public serialize(): ArrayBuffer {
    const cdaASN1 = new OctetString({ valueHex: this.cargoDeliveryAuthorization.serialize() });
    return derSerializeHeterogeneousSequence(cdaASN1);
  }
}
