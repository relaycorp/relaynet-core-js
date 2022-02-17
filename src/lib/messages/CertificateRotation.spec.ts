import { Constructed, Primitive, Sequence } from 'asn1js';

import { generateStubCert } from '../_test_utils';
import { derDeserialize } from '../crypto_wrappers/_utils';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { CertificateRotation } from './CertificateRotation';

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
    test.todo('Serialization should start with format signature');

    test.todo('Serialization should contain a sequence of a least 1 item');

    test.todo('Malformed subject certificate should be refused');

    test.todo('Malformed chain should be refused');

    test.todo('Malformed chain certificate should be refused');

    test.todo('A new instance should be returned if serialization is valid');
  });
});
