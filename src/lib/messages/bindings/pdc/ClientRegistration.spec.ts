/* tslint:disable:no-let */

import { OctetString, Sequence } from 'asn1js';
import { arrayBufferFrom, generateStubCert } from '../../../_test_utils';
import { serializeSequence } from '../../../asn1';
import { derDeserialize } from '../../../crypto_wrappers/_utils';
import Certificate from '../../../crypto_wrappers/x509/Certificate';
import InvalidMessageError from '../../InvalidMessageError';
import { ClientRegistration } from './ClientRegistration';

let clientCertificate: Certificate;
let serverCertificate: Certificate;
beforeAll(async () => {
  clientCertificate = await generateStubCert();
  serverCertificate = await generateStubCert();
});

describe('serialize', () => {
  test('Client certificate should be serialized', () => {
    const registration = new ClientRegistration(clientCertificate, serverCertificate);

    const serialization = registration.serialize();

    const sequence = derDeserialize(serialization);
    expect(sequence).toBeInstanceOf(Sequence);
    expect((sequence as Sequence).valueBlock.value[0]).toHaveProperty(
      'valueBlock.valueHex',
      clientCertificate.serialize(),
    );
  });

  test('Server certificate should be serialized', () => {
    const registration = new ClientRegistration(clientCertificate, serverCertificate);

    const serialization = registration.serialize();

    const sequence = derDeserialize(serialization);
    expect(sequence).toBeInstanceOf(Sequence);
    expect((sequence as Sequence).valueBlock.value[1]).toHaveProperty(
      'valueBlock.valueHex',
      serverCertificate.serialize(),
    );
  });
});

describe('deserialize', () => {
  test('Serialization should be DER sequence', () => {
    const invalidSerialization = arrayBufferFrom('nope.jpg');

    expect(() => ClientRegistration.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      'Serialization is not a valid ClientRegistration',
    );
  });

  test('Sequence should have at least two items', () => {
    const invalidSerialization = serializeSequence(
      new OctetString({ valueHex: arrayBufferFrom('nope.jpg') }),
    );

    expect(() => ClientRegistration.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      'Serialization is not a valid ClientRegistration',
    );
  });

  test('Invalid client certificates should be refused', () => {
    const invalidSerialization = serializeSequence(
      new OctetString({ valueHex: arrayBufferFrom('not a certificate') }),
      new OctetString({ valueHex: serverCertificate.serialize() }),
    );

    expect(() => ClientRegistration.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      /^Client certificate is invalid:/,
    );
  });

  test('Invalid server certificates should be refused', () => {
    const invalidSerialization = serializeSequence(
      new OctetString({ valueHex: serverCertificate.serialize() }),
      new OctetString({ valueHex: arrayBufferFrom('not a certificate') }),
    );

    expect(() => ClientRegistration.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      /^Server certificate is invalid:/,
    );
  });

  test('Valid registration should be accepted', () => {
    const registration = new ClientRegistration(clientCertificate, serverCertificate);

    const serialization = registration.serialize();

    const registrationDeserialized = ClientRegistration.deserialize(serialization);
    expect(registrationDeserialized.clientCertificate.isEqual(clientCertificate)).toBeTrue();
    expect(registrationDeserialized.serverCertificate.isEqual(serverCertificate)).toBeTrue();
  });
});
