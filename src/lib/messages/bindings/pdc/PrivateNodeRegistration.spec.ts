/* tslint:disable:no-let */

import { OctetString, Sequence } from 'asn1js';
import { arrayBufferFrom, generateStubCert } from '../../../_test_utils';
import { serializeSequence } from '../../../asn1';
import { derDeserialize } from '../../../crypto_wrappers/_utils';
import Certificate from '../../../crypto_wrappers/x509/Certificate';
import InvalidMessageError from '../../InvalidMessageError';
import { PrivateNodeRegistration } from './PrivateNodeRegistration';

let privateNodeCertificate: Certificate;
let gatewayCertificate: Certificate;
beforeAll(async () => {
  privateNodeCertificate = await generateStubCert();
  gatewayCertificate = await generateStubCert();
});

describe('serialize', () => {
  test('Private node certificate should be serialized', () => {
    const registration = new PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate);

    const serialization = registration.serialize();

    const sequence = derDeserialize(serialization);
    expect(sequence).toBeInstanceOf(Sequence);
    expect((sequence as Sequence).valueBlock.value[0]).toHaveProperty(
      'valueBlock.valueHex',
      privateNodeCertificate.serialize(),
    );
  });

  test('Gateway certificate should be serialized', () => {
    const registration = new PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate);

    const serialization = registration.serialize();

    const sequence = derDeserialize(serialization);
    expect(sequence).toBeInstanceOf(Sequence);
    expect((sequence as Sequence).valueBlock.value[1]).toHaveProperty(
      'valueBlock.valueHex',
      gatewayCertificate.serialize(),
    );
  });
});

describe('deserialize', () => {
  test('Serialization should be DER sequence', () => {
    const invalidSerialization = arrayBufferFrom('nope.jpg');

    expect(() => PrivateNodeRegistration.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      'Serialization is not a valid PrivateNodeRegistration',
    );
  });

  test('Sequence should have at least two items', () => {
    const invalidSerialization = serializeSequence(
      new OctetString({ valueHex: arrayBufferFrom('nope.jpg') }),
    );

    expect(() => PrivateNodeRegistration.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      'Serialization is not a valid PrivateNodeRegistration',
    );
  });

  test('Invalid private node certificates should be refused', () => {
    const invalidSerialization = serializeSequence(
      new OctetString({ valueHex: arrayBufferFrom('not a certificate') }),
      new OctetString({ valueHex: gatewayCertificate.serialize() }),
    );

    expect(() => PrivateNodeRegistration.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      /^Private node certificate is invalid:/,
    );
  });

  test('Invalid gateway certificates should be refused', () => {
    const invalidSerialization = serializeSequence(
      new OctetString({ valueHex: gatewayCertificate.serialize() }),
      new OctetString({ valueHex: arrayBufferFrom('not a certificate') }),
    );

    expect(() => PrivateNodeRegistration.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      /^Gateway certificate is invalid:/,
    );
  });

  test('Valid registration should be accepted', () => {
    const registration = new PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate);

    const serialization = registration.serialize();

    const registrationDeserialized = PrivateNodeRegistration.deserialize(serialization);
    expect(
      registrationDeserialized.privateNodeCertificate.isEqual(privateNodeCertificate),
    ).toBeTrue();
    expect(registrationDeserialized.gatewayCertificate.isEqual(gatewayCertificate)).toBeTrue();
  });
});
