import { addDays } from 'date-fns';

import {
  arrayBufferFrom,
  expectArrayBuffersToEqual,
  generateStubCert,
  reSerializeCertificate,
} from '../../_test_utils';
import { generateRSAKeyPair } from '../../crypto/keys/generation';
import { Certificate } from '../../crypto/x509/Certificate';
import { InvalidMessageError } from '../../messages/InvalidMessageError';
import { Parcel } from '../../messages/Parcel';
import { Recipient } from '../../messages/Recipient';
import {
  issueDeliveryAuthorization,
  issueEndpointCertificate,
  issueGatewayCertificate,
} from '../../pki/issuance';
import { RAMFSyntaxError } from '../../ramf/RAMFSyntaxError';
import { ParcelCollection } from './ParcelCollection';

const PARCEL_SERIALIZED = arrayBufferFrom('the parcel serialized');

let pdaGranteeKeyPair: CryptoKeyPair;
let pdaCertificate: Certificate;
let recipientCertificate: Certificate;
let gatewayCertificate: Certificate;
beforeAll(async () => {
  const tomorrow = addDays(new Date(), 1);

  const caKeyPair = await generateRSAKeyPair();
  gatewayCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerPrivateKey: caKeyPair.privateKey,
      subjectPublicKey: caKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );

  const recipientKeyPair = await generateRSAKeyPair();
  recipientCertificate = reSerializeCertificate(
    await issueEndpointCertificate({
      issuerCertificate: gatewayCertificate,
      issuerPrivateKey: caKeyPair.privateKey,
      subjectPublicKey: recipientKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );

  pdaGranteeKeyPair = await generateRSAKeyPair();
  pdaCertificate = reSerializeCertificate(
    await issueDeliveryAuthorization({
      issuerCertificate: recipientCertificate,
      issuerPrivateKey: recipientKeyPair.privateKey,
      subjectPublicKey: pdaGranteeKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );
});

let recipient: Recipient;
beforeAll(async () => {
  recipient = {
    id: await recipientCertificate.calculateSubjectId(),
  };
});

test('Parcel serialized should be honored', () => {
  const collection = new ParcelCollection(PARCEL_SERIALIZED, [gatewayCertificate], jest.fn());

  expectArrayBuffersToEqual(PARCEL_SERIALIZED, collection.parcelSerialized);
});

test('Trusted certificates should be honored', () => {
  const collection = new ParcelCollection(PARCEL_SERIALIZED, [gatewayCertificate], jest.fn());

  expect(collection.trustedCertificates).toEqual([gatewayCertificate]);
});

test('ACK callback should be honored', async () => {
  const ackCallback = jest.fn();
  const collection = new ParcelCollection(PARCEL_SERIALIZED, [gatewayCertificate], ackCallback);

  await collection.ack();

  expect(ackCallback).toBeCalled();
});

describe('deserializeAndValidateParcel', () => {
  test('Malformed parcels should be refused', async () => {
    const collection = new ParcelCollection(
      arrayBufferFrom('invalid'),
      [gatewayCertificate],
      jest.fn(),
    );

    await expect(collection.deserializeAndValidateParcel()).rejects.toBeInstanceOf(RAMFSyntaxError);
  });

  test('Parcels from unauthorized senders should be refused', async () => {
    const unauthorizedSenderCertificate = await generateStubCert({
      issuerPrivateKey: pdaGranteeKeyPair.privateKey,
      subjectPublicKey: pdaGranteeKeyPair.publicKey,
    });
    const parcel = new Parcel(recipient, unauthorizedSenderCertificate, Buffer.from([]));
    const collection = new ParcelCollection(
      await parcel.serialize(pdaGranteeKeyPair.privateKey),
      [gatewayCertificate],
      jest.fn(),
    );

    await expect(collection.deserializeAndValidateParcel()).rejects.toBeInstanceOf(
      InvalidMessageError,
    );
  });

  test('Valid parcels should be returned', async () => {
    const parcel = new Parcel(recipient, pdaCertificate, Buffer.from([]), {
      senderCaCertificateChain: [recipientCertificate],
    });
    const collection = new ParcelCollection(
      await parcel.serialize(pdaGranteeKeyPair.privateKey),
      [gatewayCertificate],
      jest.fn(),
    );

    const parcelDeserialized = await collection.deserializeAndValidateParcel();
    expect(parcelDeserialized.id).toEqual(parcel.id);
  });
});
