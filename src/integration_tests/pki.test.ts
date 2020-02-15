// tslint:disable:no-let

import {
  Certificate,
  generateRSAKeyPair,
  issueDeliveryAuthorization,
  issueEndpointCertificate,
  issueGatewayCertificate,
  Parcel,
} from '..';
import { generateStubCert, reSerializeCertificate } from '../lib/_test_utils';

const TOMORROW = new Date();
TOMORROW.setDate(TOMORROW.getDate() + 1);

let publicGatewayCert: Certificate;
let privateGatewayCert: Certificate;
let peerEndpointCert: Certificate;
let endpointPdaCert: Certificate;
beforeAll(async () => {
  const publicGatewayKeyPair = await generateRSAKeyPair();
  publicGatewayCert = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerPrivateKey: publicGatewayKeyPair.privateKey,
      subjectPublicKey: publicGatewayKeyPair.publicKey,
      validityEndDate: TOMORROW,
    }),
  );

  const localGatewayKeyPair = await generateRSAKeyPair();
  privateGatewayCert = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: publicGatewayCert,
      issuerPrivateKey: publicGatewayKeyPair.privateKey,
      subjectPublicKey: localGatewayKeyPair.publicKey,
      validityEndDate: TOMORROW,
    }),
  );

  const peerEndpointKeyPair = await generateRSAKeyPair();
  peerEndpointCert = reSerializeCertificate(
    await issueEndpointCertificate({
      issuerCertificate: privateGatewayCert,
      issuerPrivateKey: localGatewayKeyPair.privateKey,
      subjectPublicKey: peerEndpointKeyPair.publicKey,
      validityEndDate: TOMORROW,
    }),
  );

  const endpointKeyPair = await generateRSAKeyPair();
  endpointPdaCert = reSerializeCertificate(
    await issueDeliveryAuthorization({
      issuerCertificate: peerEndpointCert,
      issuerPrivateKey: peerEndpointKeyPair.privateKey,
      subjectPublicKey: endpointKeyPair.publicKey,
      validityEndDate: TOMORROW,
    }),
  );
});

test('Messages by authorized senders should be accepted', async () => {
  const parcel = new Parcel(
    await peerEndpointCert.calculateSubjectPrivateAddress(),
    endpointPdaCert,
    Buffer.from('hey'),
    { senderCaCertificateChain: [peerEndpointCert, privateGatewayCert] },
  );

  await parcel.validate([publicGatewayCert]);
});

test('Certificate chain should be computed corrected', async () => {
  const parcel = new Parcel(
    await peerEndpointCert.calculateSubjectPrivateAddress(),
    endpointPdaCert,
    Buffer.from('hey'),
    { senderCaCertificateChain: [peerEndpointCert, privateGatewayCert] },
  );

  await expect(parcel.getSenderCertificationPath([publicGatewayCert])).resolves.toEqual([
    endpointPdaCert,
    peerEndpointCert,
    privateGatewayCert,
    publicGatewayCert,
  ]);
});

test('Messages by unauthorized senders should be refused', async () => {
  const parcel = new Parcel(
    await peerEndpointCert.calculateSubjectPrivateAddress(),
    await generateStubCert(),
    Buffer.from('hey'),
    { senderCaCertificateChain: [peerEndpointCert, privateGatewayCert] },
  );

  await expect(parcel.validate([publicGatewayCert])).rejects.toHaveProperty(
    'message',
    'Sender is not authorized: No valid certificate paths found',
  );
});
