import { addDays, subSeconds } from 'date-fns';

import {
  Certificate,
  generateRSAKeyPair,
  issueDeliveryAuthorization,
  issueEndpointCertificate,
  issueGatewayCertificate,
  Parcel,
} from '..';
import { reSerializeCertificate } from '../lib/_test_utils';

const ONE_SECOND_AGO = subSeconds(new Date(), 1);

const TOMORROW = addDays(new Date(), 1);

let internetGatewayCert: Certificate;
let privateGatewayCert: Certificate;
let peerEndpointId: string;
let peerEndpointCert: Certificate;
let endpointPdaCert: Certificate;
beforeAll(async () => {
  const internetGatewayKeyPair = await generateRSAKeyPair();
  internetGatewayCert = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerPrivateKey: internetGatewayKeyPair.privateKey,
      subjectPublicKey: internetGatewayKeyPair.publicKey,
      validityEndDate: TOMORROW,
      validityStartDate: ONE_SECOND_AGO,
    }),
  );

  const localGatewayKeyPair = await generateRSAKeyPair();
  privateGatewayCert = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: internetGatewayCert,
      issuerPrivateKey: internetGatewayKeyPair.privateKey,
      subjectPublicKey: localGatewayKeyPair.publicKey,
      validityEndDate: TOMORROW,
      validityStartDate: ONE_SECOND_AGO,
    }),
  );

  const peerEndpointKeyPair = await generateRSAKeyPair();
  peerEndpointCert = reSerializeCertificate(
    await issueEndpointCertificate({
      issuerCertificate: privateGatewayCert,
      issuerPrivateKey: localGatewayKeyPair.privateKey,
      subjectPublicKey: peerEndpointKeyPair.publicKey,
      validityEndDate: TOMORROW,
      validityStartDate: ONE_SECOND_AGO,
    }),
  );

  peerEndpointId = await peerEndpointCert.calculateSubjectId();

  const endpointKeyPair = await generateRSAKeyPair();
  endpointPdaCert = reSerializeCertificate(
    await issueDeliveryAuthorization({
      issuerCertificate: peerEndpointCert,
      issuerPrivateKey: peerEndpointKeyPair.privateKey,
      subjectPublicKey: endpointKeyPair.publicKey,
      validityEndDate: TOMORROW,
      validityStartDate: ONE_SECOND_AGO,
    }),
  );
});

test('Messages by authorized senders should be accepted', async () => {
  const parcel = new Parcel({ id: peerEndpointId }, endpointPdaCert, Buffer.from('hey'), {
    creationDate: ONE_SECOND_AGO,
    senderCaCertificateChain: [peerEndpointCert, privateGatewayCert],
  });

  await parcel.validate([internetGatewayCert]);
});

test('Certificate chain should be computed corrected', async () => {
  const parcel = new Parcel({ id: peerEndpointId }, endpointPdaCert, Buffer.from('hey'), {
    senderCaCertificateChain: [peerEndpointCert, privateGatewayCert],
  });

  await expect(parcel.getSenderCertificationPath([internetGatewayCert])).resolves.toEqual([
    expect.toSatisfy((c) => c.isEqual(endpointPdaCert)),
    expect.toSatisfy((c) => c.isEqual(peerEndpointCert)),
    expect.toSatisfy((c) => c.isEqual(privateGatewayCert)),
    expect.toSatisfy((c) => c.isEqual(internetGatewayCert)),
  ]);
});

test('Messages by unauthorized senders should be refused', async () => {
  const keyPair = await generateRSAKeyPair();
  const unauthorizedSenderCertificate = reSerializeCertificate(
    await issueEndpointCertificate({
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
      validityEndDate: TOMORROW,
      validityStartDate: ONE_SECOND_AGO,
    }),
  );
  const parcel = new Parcel(
    { id: peerEndpointId },
    unauthorizedSenderCertificate,
    Buffer.from('hey'),
    {
      creationDate: ONE_SECOND_AGO,
      senderCaCertificateChain: [peerEndpointCert, privateGatewayCert],
    },
  );

  await expect(parcel.validate([internetGatewayCert])).rejects.toHaveProperty(
    'message',
    'Sender is not authorized: No valid certificate paths found',
  );
});
