import { Constructed, Integer, OctetString, Sequence, Set, VisibleString } from 'asn1js';
import { addDays } from 'date-fns';

import { expectArrayBuffersToEqual } from '../_test_utils';
import { makeImplicitlyTaggedSequence } from '../asn1';
import { derDeserialize } from '../crypto/_utils';
import { generateRSAKeyPair } from '../crypto/keys';
import { Certificate } from '../crypto/x509/Certificate';
import { InvalidMessageError } from '../messages/InvalidMessageError';
import { CertificationPath } from './CertificationPath';
import { issueGatewayCertificate } from './issuance';

let subjectCertificate: Certificate;
let issuerCertificate: Certificate;
beforeAll(async () => {
  const issuerKeyPair = await generateRSAKeyPair();
  issuerCertificate = await issueGatewayCertificate({
    subjectPublicKey: issuerKeyPair.publicKey,
    issuerPrivateKey: issuerKeyPair.privateKey,
    validityEndDate: addDays(new Date(), 1),
  });

  const subjectKeyPair = await generateRSAKeyPair();
  subjectCertificate = await issueGatewayCertificate({
    issuerCertificate,
    issuerPrivateKey: issuerKeyPair.privateKey,
    subjectPublicKey: subjectKeyPair.publicKey,
    validityEndDate: issuerCertificate.expiryDate,
  });
});

describe('serialize', () => {
  test('Leaf certificate should be serialized', () => {
    const path = new CertificationPath(subjectCertificate, [issuerCertificate]);

    const serialization = path.serialize();

    const pathDeserialized = derDeserialize(serialization) as Sequence;
    const leafCertificateASN1 = pathDeserialized.valueBlock.value[0];
    expectArrayBuffersToEqual(
      leafCertificateASN1.valueBlock.toBER(),
      subjectCertificate.serialize(),
    );
  });

  test('Chain should be serialized', () => {
    const path = new CertificationPath(subjectCertificate, [issuerCertificate]);

    const serialization = path.serialize();

    const pathDeserialized = derDeserialize(serialization) as Sequence;
    const casASN1 = pathDeserialized.valueBlock.value[1] as Sequence;
    expect(casASN1).toBeInstanceOf(Constructed);
    expect(casASN1.valueBlock.value).toHaveLength(1);
    const caASN1 = casASN1.valueBlock.value[0];
    expectArrayBuffersToEqual(caASN1.valueBlock.toBER(), issuerCertificate.serialize());
  });
});

describe('deserialize', () => {
  test('Serialization should contain a sequence of a least 2 items', async () => {
    const invalidSerialization = makeImplicitlyTaggedSequence(
      new OctetString(), // Just one item instead of 2+
    ).toBER(false);

    expect(() => CertificationPath.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      'Serialization did not meet structure of a CertificationPath',
    );
  });

  test('Malformed subject certificate should be refused', async () => {
    const invalidSerialization = makeImplicitlyTaggedSequence(
      new VisibleString({ value: 'This is supposed to be a cert' }),
      new Set(),
    ).toBER(false);

    expect(() => CertificationPath.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      'Leaf certificate is malformed',
    );
  });

  test('Malformed chain should be refused', async () => {
    const invalidSerialization = makeImplicitlyTaggedSequence(
      new OctetString({ valueHex: subjectCertificate.serialize() }),
      new Integer({ value: 42 }),
    ).toBER(false);

    expect(() => CertificationPath.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      'Serialization did not meet structure of a CertificationPath',
    );
  });

  test('Malformed chain certificate should be refused', async () => {
    const invalidSerialization = makeImplicitlyTaggedSequence(
      new OctetString({ valueHex: subjectCertificate.serialize() }),
      makeImplicitlyTaggedSequence(new VisibleString({ value: 'This is a "certificate" ;-)' })),
    ).toBER(false);

    expect(() => CertificationPath.deserialize(invalidSerialization)).toThrowWithMessage(
      InvalidMessageError,
      'Certificate authorities contain malformed certificate',
    );
  });

  test('A new instance should be returned if serialization is valid', async () => {
    const rotation = new CertificationPath(subjectCertificate, [issuerCertificate]);
    const serialization = rotation.serialize();

    const rotationDeserialized = CertificationPath.deserialize(serialization);

    expect(rotationDeserialized.leafCertificate.isEqual(subjectCertificate)).toBeTrue();
    expect(rotationDeserialized.certificateAuthorities).toHaveLength(1);
    expect(rotationDeserialized.certificateAuthorities[0].isEqual(issuerCertificate));
  });
});
