// tslint:disable:no-let

import { ObjectIdentifier, OctetString } from 'asn1js';

import { arrayBufferFrom, generateStubCert, reSerializeCertificate } from '../../_test_utils';
import { serializeSequence } from '../../asn1';
import CMSError from '../../crypto_wrappers/cms/CMSError';
import { SignedData } from '../../crypto_wrappers/cms/signedData';
import { generateRSAKeyPair } from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { RELAYNET_OIDS } from '../../oids';
import { Countersigner, NONCE_SIGNATURE, PARCEL_DELIVERY } from './Countersigner';

const PLAINTEXT = arrayBufferFrom('the plaintext');

let CA_CERTIFICATE: Certificate;
let SIGNER_PRIVATE_KEY: CryptoKey;
let SIGNER_CERTIFICATE: Certificate;
beforeAll(async () => {
  const caKeyPair = await generateRSAKeyPair();
  CA_CERTIFICATE = reSerializeCertificate(
    await generateStubCert({
      attributes: { isCA: true },
      issuerPrivateKey: caKeyPair.privateKey,
      subjectPublicKey: caKeyPair.publicKey,
    }),
  );

  const signerKeyPair = await generateRSAKeyPair();
  SIGNER_PRIVATE_KEY = signerKeyPair.privateKey;

  SIGNER_CERTIFICATE = await generateStubCert({
    issuerCertificate: CA_CERTIFICATE,
    issuerPrivateKey: caKeyPair.privateKey,
    subjectPublicKey: signerKeyPair.publicKey,
  });
});

describe('Countersigner', () => {
  const OID_VALUE = '1.2.3.4';
  const OID = new ObjectIdentifier({ value: OID_VALUE });

  describe('sign', () => {
    test('Plaintext should not be encapsulated', async () => {
      const countersigner = new Countersigner(OID_VALUE);

      const countersignature = await countersigner.sign(
        PLAINTEXT,
        SIGNER_PRIVATE_KEY,
        SIGNER_CERTIFICATE,
      );

      const signedData = SignedData.deserialize(countersignature);
      expect(signedData.plaintext).toBeNull();
    });

    test('Certificate should be encapsulated', async () => {
      const countersigner = new Countersigner(OID_VALUE);

      const countersignature = await countersigner.sign(
        PLAINTEXT,
        SIGNER_PRIVATE_KEY,
        SIGNER_CERTIFICATE,
      );

      const signedData = SignedData.deserialize(countersignature);
      expect(signedData.signerCertificate).not.toBeNull();
    });

    test('Signature should validate', async () => {
      const countersigner = new Countersigner(OID_VALUE);

      const countersignature = await countersigner.sign(
        PLAINTEXT,
        SIGNER_PRIVATE_KEY,
        SIGNER_CERTIFICATE,
      );

      const signedData = SignedData.deserialize(countersignature);
      const expectedPlaintext = serializeSequence(OID, new OctetString({ valueHex: PLAINTEXT }));
      await signedData.verify(expectedPlaintext);
    });
  });

  describe('verify', () => {
    test('Malformed signatures should be refused', async () => {
      const countersigner = new Countersigner(OID_VALUE);

      const countersignature = arrayBufferFrom('not valid');

      await expect(
        countersigner.verify(countersignature, PLAINTEXT, [CA_CERTIFICATE]),
      ).rejects.toBeInstanceOf(CMSError);
    });

    test('Invalid signatures should be refused', async () => {
      const countersigner = new Countersigner(OID_VALUE);
      const differentKeyPair = await generateRSAKeyPair();

      const countersignature = await countersigner.sign(
        PLAINTEXT,
        differentKeyPair.privateKey,
        SIGNER_CERTIFICATE,
      );

      await expect(
        countersigner.verify(countersignature, PLAINTEXT, [CA_CERTIFICATE]),
      ).rejects.toBeInstanceOf(CMSError);
    });

    test('Untrusted signers should be refused', async () => {
      const countersigner = new Countersigner(OID_VALUE);

      const countersignature = await countersigner.sign(
        PLAINTEXT,
        SIGNER_PRIVATE_KEY,
        SIGNER_CERTIFICATE,
      );

      await expect(countersigner.verify(countersignature, PLAINTEXT, [])).rejects.toBeInstanceOf(
        CMSError,
      );
    });

    test('Signer certificate should be output if trusted and signature is valid', async () => {
      const countersigner = new Countersigner(OID_VALUE);

      const countersignature = await countersigner.sign(
        PLAINTEXT,
        SIGNER_PRIVATE_KEY,
        SIGNER_CERTIFICATE,
      );

      const countersignerCertificate = await countersigner.verify(countersignature, PLAINTEXT, [
        CA_CERTIFICATE,
      ]);
      await expect(countersignerCertificate.isEqual(SIGNER_CERTIFICATE)).toBeTrue();
    });
  });
});

describe('Countersignature objects', () => {
  test('PARCEL_DELIVERY should use the right OID', () => {
    expect(PARCEL_DELIVERY.oid).toEqual(RELAYNET_OIDS.COUNTERSIGNATURE.PARCEL_DELIVERY);
  });

  test('NONCE_SIGNATURE should use the right OID', () => {
    expect(NONCE_SIGNATURE.oid).toEqual(RELAYNET_OIDS.COUNTERSIGNATURE.NONCE_SIGNATURE);
  });
});
