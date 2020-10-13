import { generateRSAKeyPair } from '../../../..';
import { arrayBufferFrom, expectBuffersToEqual, generateStubCert } from '../../../_test_utils';
import Certificate from '../../../crypto_wrappers/x509/Certificate';
import RAMFSyntaxError from '../../../ramf/RAMFSyntaxError';
import { ParcelCollection } from './ParcelCollection';

const PARCEL_SERIALIZED = arrayBufferFrom('the parcel serialized');

let keyPair: CryptoKeyPair;
let certificate: Certificate;
let caCertificate: Certificate;
beforeAll(async () => {
  const caKeyPair = await generateRSAKeyPair();
  caCertificate = await generateStubCert({
    attributes: { isCA: true },
    issuerPrivateKey: caKeyPair.privateKey,
    subjectPublicKey: caKeyPair.publicKey,
  });

  keyPair = await generateRSAKeyPair();
  certificate = await generateStubCert({
    issuerCertificate: caCertificate,
    issuerPrivateKey: caKeyPair.privateKey,
    subjectPublicKey: keyPair.publicKey,
  });
});

test('Parcel serialized should be honored', () => {
  const collection = new ParcelCollection(PARCEL_SERIALIZED, [certificate], jest.fn());

  expectBuffersToEqual(PARCEL_SERIALIZED, collection.parcelSerialized);
});

test('Trusted certificates should be honored', () => {
  const collection = new ParcelCollection(PARCEL_SERIALIZED, [certificate], jest.fn());

  expect(collection.trustedCertificates).toEqual([certificate]);
});

test('ACK callback should be honored', async () => {
  const ackCallback = jest.fn();
  const collection = new ParcelCollection(PARCEL_SERIALIZED, [certificate], ackCallback);

  await collection.ack();

  expect(ackCallback).toBeCalled();
});

describe('deserializeAndValidateParcel', () => {
  test('Malformed parcels should be refused', async () => {
    const collection = new ParcelCollection(arrayBufferFrom('invalid'), [certificate], jest.fn());

    await expect(collection.deserializeAndValidateParcel()).rejects.toBeInstanceOf(RAMFSyntaxError);
  });

  test.todo('Parcels bound for public endpoints should be refused');

  test.todo('Parcels from unauthorized senders should be refused');

  test.todo('Valid parcels should be returned');
});
