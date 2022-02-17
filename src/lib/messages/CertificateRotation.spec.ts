import { Constructed, Integer, OctetString, Primitive, Sequence, Set, VisibleString } from 'asn1js';

import { arrayBufferFrom, generateStubCert } from '../_test_utils';
import { makeImplicitlyTaggedSequence } from '../asn1';
import { derDeserialize } from '../crypto_wrappers/_utils';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { CERTIFICATE_ROTATION_FORMAT_SIGNATURE, CertificateRotation } from './CertificateRotation';
import InvalidMessageError from './InvalidMessageError';

describe('CertificateRotation', () => {
  let subjectCertificate: Certificate;
  let issuerCertificate: Certificate;
  beforeAll(async () => {
    subjectCertificate = await generateStubCert();
    issuerCertificate = await generateStubCert();
  });

  describe('serialize', () => {
    test('Serialization should start with format signature', async () => {
      const rotation = new CertificateRotation(subjectCertificate, [issuerCertificate]);

      const serialization = rotation.serialize();

      const expectedFormatSignature = Buffer.concat([
        Buffer.from('Relaynet'),
        Buffer.from([0x10, 0x00]),
      ]);
      expect(Buffer.from(serialization).slice(0, 10)).toEqual(expectedFormatSignature);
    });

    test('Serialization should contain a 2-item sequence', async () => {
      const rotation = new CertificateRotation(subjectCertificate, [issuerCertificate]);

      const serialization = rotation.serialize();

      const sequence = parseRotation(serialization);
      expect(sequence.valueBlock.value).toHaveLength(2);
    });

    test('Subject certificate should be in sequence', async () => {
      const rotation = new CertificateRotation(subjectCertificate, [issuerCertificate]);

      const serialization = rotation.serialize();

      const sequence = parseRotation(serialization);
      const subjectCertificateASN1 = sequence.valueBlock.value[0];
      const certificate = Certificate.deserialize(
        (subjectCertificateASN1 as Primitive).valueBlock.valueHex,
      );
      expect(subjectCertificate.isEqual(certificate)).toBeTrue();
    });

    test('Chain certificates should be in sequence', async () => {
      const rotation = new CertificateRotation(subjectCertificate, [issuerCertificate]);

      const serialization = rotation.serialize();

      const sequence = parseRotation(serialization);
      const chainASN1 = sequence.valueBlock.value[1];
      expect(chainASN1).toBeInstanceOf(Constructed);
      const chainCertsSerialized = (chainASN1 as Constructed).valueBlock.value.map(
        (c) => (c as Primitive).valueBlock.valueHex,
      );
      expect(chainCertsSerialized).toHaveLength(1);
      const certificate = Certificate.deserialize(chainCertsSerialized[0]);
      expect(issuerCertificate.isEqual(certificate)).toBeTrue();
    });

    function parseRotation(serialization: ArrayBuffer): Sequence {
      const sequenceSerialized = serialization.slice(10);
      const sequence = derDeserialize(sequenceSerialized);
      expect(sequence).toBeInstanceOf(Sequence);
      return sequence as Sequence;
    }
  });

  describe('deserialize', () => {
    test('Serialization should start with format signature', () => {
      const invalidSerialization = arrayBufferFrom('RelaynetA0');

      expect(() => CertificateRotation.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Format signature should be that of a CertificateRotation',
      );
    });

    test('Serialization should contain a sequence of a least 2 items', async () => {
      const invalidSerialization = arrayBufferFrom([
        ...CERTIFICATE_ROTATION_FORMAT_SIGNATURE,
        ...Buffer.from(
          makeImplicitlyTaggedSequence(
            new VisibleString(), // Just one item instead of 2+
          ).toBER(false),
        ),
      ]);

      expect(() => CertificateRotation.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Serialization did not meet structure of a CertificateRotation',
      );
    });

    test('Malformed subject certificate should be refused', async () => {
      const invalidSerialization = arrayBufferFrom([
        ...CERTIFICATE_ROTATION_FORMAT_SIGNATURE,
        ...Buffer.from(
          makeImplicitlyTaggedSequence(
            new VisibleString({ value: 'This is supposed to be a cert' }),
            new Set(),
          ).toBER(false),
        ),
      ]);

      expect(() => CertificateRotation.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Subject certificate is malformed',
      );
    });

    test('Malformed chain should be refused', async () => {
      const invalidSerialization = arrayBufferFrom([
        ...CERTIFICATE_ROTATION_FORMAT_SIGNATURE,
        ...Buffer.from(
          makeImplicitlyTaggedSequence(
            new OctetString({ valueHex: subjectCertificate.serialize() }),
            new Integer({ value: 42 }),
          ).toBER(false),
        ),
      ]);

      expect(() => CertificateRotation.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Serialization did not meet structure of a CertificateRotation',
      );
    });

    test('Malformed chain certificate should be refused', async () => {
      const invalidSerialization = arrayBufferFrom([
        ...CERTIFICATE_ROTATION_FORMAT_SIGNATURE,
        ...Buffer.from(
          makeImplicitlyTaggedSequence(
            new OctetString({ valueHex: subjectCertificate.serialize() }),
            makeImplicitlyTaggedSequence(
              new VisibleString({ value: 'This is a "certificate" ;-)' }),
            ),
          ).toBER(false),
        ),
      ]);

      expect(() => CertificateRotation.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Chain contains malformed certificate',
      );
    });

    test('A new instance should be returned if serialization is valid', async () => {
      const rotation = new CertificateRotation(subjectCertificate, [issuerCertificate]);
      const serialization = rotation.serialize();

      const rotationDeserialized = CertificateRotation.deserialize(serialization);

      expect(rotationDeserialized.subjectCertificate.isEqual(subjectCertificate)).toBeTrue();
      expect(rotationDeserialized.chain).toHaveLength(1);
      expect(rotationDeserialized.chain[0].isEqual(issuerCertificate));
    });
  });
});
