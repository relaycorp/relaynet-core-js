import { Integer } from 'asn1js';

import {
  arrayBufferFrom,
  expectArrayBuffersToEqual,
  generateStubCert,
  getPrimitiveItemFromConstructed,
} from '../../_test_utils';
import { makeImplicitlyTaggedSequence } from '../../asn1';
import { derDeserialize } from '../../crypto_wrappers/_utils';
import { Certificate } from '../../crypto_wrappers/x509/Certificate';
import { InvalidMessageError } from '../InvalidMessageError';
import { CargoCollectionRequest } from './CargoCollectionRequest';

let cargoDeliveryAuthorization: Certificate;
beforeAll(async () => {
  cargoDeliveryAuthorization = await generateStubCert();
});

describe('serialize', () => {
  test('Cargo Delivery Authorization should be included DER-encoded', () => {
    const request = new CargoCollectionRequest(cargoDeliveryAuthorization);

    const serialization = request.serialize();

    const sequence = derDeserialize(serialization);
    const cdaSerialized = getPrimitiveItemFromConstructed(sequence, 0).valueBlock.valueHex;
    expectArrayBuffersToEqual(cargoDeliveryAuthorization.serialize(), cdaSerialized);
  });
});

describe('deserialize', () => {
  test('Malformed sequences should be refused', () => {
    expect(() =>
      CargoCollectionRequest.deserialize(arrayBufferFrom('malformed')),
    ).toThrowWithMessage(
      InvalidMessageError,
      'Serialization is not a valid CargoCollectionRequest',
    );
  });

  test('Sequence should have at least one item', () => {
    expect(() =>
      CargoCollectionRequest.deserialize(makeImplicitlyTaggedSequence().toBER()),
    ).toThrowWithMessage(
      InvalidMessageError,
      'Serialization is not a valid CargoCollectionRequest',
    );
  });

  test('Malformed Cargo Delivery Authorizations should be refused', () => {
    const invalidCertificate = new Integer({ value: 42 });
    expect(() =>
      CargoCollectionRequest.deserialize(makeImplicitlyTaggedSequence(invalidCertificate).toBER()),
    ).toThrowWithMessage(
      InvalidMessageError,
      /^CargoCollectionRequest contains a malformed Cargo Delivery Authorization: /,
    );
  });

  test('Valid values should be accepted', () => {
    const request = new CargoCollectionRequest(cargoDeliveryAuthorization);

    const requestDeserialized = CargoCollectionRequest.deserialize(request.serialize());

    expect(
      requestDeserialized.cargoDeliveryAuthorization.isEqual(cargoDeliveryAuthorization),
    ).toBeTrue();
  });
});
