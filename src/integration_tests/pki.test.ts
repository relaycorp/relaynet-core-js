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

let relayingGatewayCert: Certificate;
let localGatewayCert: Certificate;
let peerEndpointCert: Certificate;
let endpointPdaCert: Certificate;
beforeAll(async () => {
  const relayingGatewayKeyPair = await generateRSAKeyPair();
  relayingGatewayCert = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerPrivateKey: relayingGatewayKeyPair.privateKey,
      subjectPublicKey: relayingGatewayKeyPair.publicKey,
      validityEndDate: TOMORROW,
    }),
  );

  const localGatewayKeyPair = await generateRSAKeyPair();
  localGatewayCert = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: relayingGatewayCert,
      issuerPrivateKey: relayingGatewayKeyPair.privateKey,
      subjectPublicKey: localGatewayKeyPair.publicKey,
      validityEndDate: TOMORROW,
    }),
  );

  const peerEndpointKeyPair = await generateRSAKeyPair();
  peerEndpointCert = reSerializeCertificate(
    await issueEndpointCertificate({
      issuerCertificate: localGatewayCert,
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
    { senderCaCertificateChain: [peerEndpointCert, localGatewayCert] },
  );

  await parcel.validate([relayingGatewayCert]);
});

test('Certificate chain should be computed corrected', async () => {
  const parcel = new Parcel(
    await peerEndpointCert.calculateSubjectPrivateAddress(),
    endpointPdaCert,
    Buffer.from('hey'),
    { senderCaCertificateChain: [peerEndpointCert, localGatewayCert] },
  );

  await expect(parcel.getSenderCertificationPath([relayingGatewayCert])).resolves.toEqual([
    endpointPdaCert,
    peerEndpointCert,
    localGatewayCert,
    relayingGatewayCert,
  ]);
});

test('Messages by unauthorized senders should be refused', async () => {
  const parcel = new Parcel(
    await peerEndpointCert.calculateSubjectPrivateAddress(),
    await generateStubCert(),
    Buffer.from('hey'),
    { senderCaCertificateChain: [peerEndpointCert, localGatewayCert] },
  );

  await expect(parcel.validate([relayingGatewayCert])).rejects.toHaveProperty(
    'message',
    'Sender is not authorized: No valid certificate paths found',
  );
});
