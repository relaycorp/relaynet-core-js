import { VisibleString } from 'asn1js';

import { arrayBufferFrom, catchError, generateStubCert } from '../_test_utils';
import { makeImplicitlyTaggedSequence } from '../asn1';
import { Certificate } from '../crypto_wrappers/x509/Certificate';
import { CertificationPath } from '../pki/CertificationPath';
import { CERTIFICATE_ROTATION_FORMAT_SIGNATURE, CertificateRotation } from './CertificateRotation';
import { InvalidMessageError } from './InvalidMessageError';

describe('CertificateRotation', () => {
  let subjectCertificate: Certificate;
  let issuerCertificate: Certificate;
  let certificationPath: CertificationPath;
  beforeAll(async () => {
    subjectCertificate = await generateStubCert();
    issuerCertificate = await generateStubCert();
    certificationPath = new CertificationPath(subjectCertificate, [issuerCertificate]);
  });

  describe('serialize', () => {
    test('Serialization should start with format signature', async () => {
      const rotation = new CertificateRotation(certificationPath);

      const serialization = rotation.serialize();

      const expectedFormatSignature = Buffer.concat([
        Buffer.from('Awala'),
        Buffer.from([0x10, 0x00]),
      ]);
      expect(Buffer.from(serialization).slice(0, 7)).toEqual(expectedFormatSignature);
    });

    test('Serialization should contain CertificationPath', async () => {
      const rotation = new CertificateRotation(certificationPath);

      const pathSerialized = rotation.serialize().slice(7);

      expect(pathSerialized).toEqual(certificationPath.serialize());
    });
  });

  describe('deserialize', () => {
    test('Serialization should start with format signature', () => {
      const invalidSerialization = arrayBufferFrom('RelaynetA0');

      expect(() => CertificateRotation.deserialize(invalidSerialization)).toThrowWithMessage(
        InvalidMessageError,
        'Format signature should be that of a CertificateRotation',
      );
    });

    test('Serialization should contain a well-formed CertificationPath', async () => {
      const invalidSerialization = arrayBufferFrom([
        ...CERTIFICATE_ROTATION_FORMAT_SIGNATURE,
        ...Buffer.from(
          makeImplicitlyTaggedSequence(
            new VisibleString(), // Just one item instead of 2+
          ).toBER(false),
        ),
      ]);

      const error = catchError(
        () => CertificateRotation.deserialize(invalidSerialization),
        InvalidMessageError,
      );

      expect(error.message).toStartWith('CertificationPath is malformed');
      expect(error.cause()).toBeInstanceOf(InvalidMessageError);
    });

    test('A new instance should be returned if serialization is valid', async () => {
      const rotation = new CertificateRotation(certificationPath);
      const serialization = rotation.serialize();

      const rotationDeserialized = CertificateRotation.deserialize(serialization);

      expect(
        rotationDeserialized.certificationPath.leafCertificate.isEqual(subjectCertificate),
      ).toBeTrue();
      expect(rotationDeserialized.certificationPath.certificateAuthorities).toHaveLength(1);
      expect(
        rotationDeserialized.certificationPath.certificateAuthorities[0].isEqual(issuerCertificate),
      );
    });
  });
});
