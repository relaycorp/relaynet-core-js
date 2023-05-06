import { generateStubCert } from '../../_test_utils';
import { generateRSAKeyPair } from '../../crypto_wrappers/keys';
import { Certificate } from '../../crypto_wrappers/x509/Certificate';
import { RELAYNET_OIDS } from '../../oids';
import {
  ParcelCollectionHandshakeSigner,
  ParcelCollectionHandshakeVerifier,
  ParcelDeliverySigner,
  ParcelDeliveryVerifier,
} from './signatures';

let signerPrivateKey: CryptoKey;
let signerCertificate: Certificate;
let caCertificate: Certificate;
beforeAll(async () => {
  const caKeyPair = await generateRSAKeyPair();
  caCertificate = await generateStubCert({
    attributes: { isCA: true },
    issuerPrivateKey: caKeyPair.privateKey,
    subjectPublicKey: caKeyPair.publicKey,
  });

  const signerKeyPair = await generateRSAKeyPair();
  signerPrivateKey = signerKeyPair.privateKey;
  signerCertificate = await generateStubCert({
    issuerCertificate: caCertificate,
    issuerPrivateKey: caKeyPair.privateKey,
    subjectPublicKey: signerKeyPair.publicKey,
  });
});

describe('Parcel collection', () => {
  test('Signer should use correct OID', () => {
    const signer = new ParcelCollectionHandshakeSigner(signerCertificate, signerPrivateKey);

    expect(signer.oid).toEqual(RELAYNET_OIDS.SIGNATURE.PARCEL_COLLECTION_HANDSHAKE);
  });

  test('Verifier should use correct OID', () => {
    const verifier = new ParcelCollectionHandshakeVerifier([caCertificate]);

    expect(verifier.oid).toEqual(RELAYNET_OIDS.SIGNATURE.PARCEL_COLLECTION_HANDSHAKE);
  });
});

describe('Parcel delivery', () => {
  test('Signer should use correct OID', () => {
    const signer = new ParcelDeliverySigner(signerCertificate, signerPrivateKey);

    expect(signer.oid).toEqual(RELAYNET_OIDS.SIGNATURE.PARCEL_DELIVERY);
  });

  test('Verifier should use correct OID', () => {
    const verifier = new ParcelDeliveryVerifier([caCertificate]);

    expect(verifier.oid).toEqual(RELAYNET_OIDS.SIGNATURE.PARCEL_DELIVERY);
  });
});
