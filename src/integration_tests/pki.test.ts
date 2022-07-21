import {
  Certificate,
  generateRSAKeyPair,
  issueDeliveryAuthorization,
  issueEndpointCertificate,
  issueGatewayCertificate,
  Parcel,
} from '..';
import { reSerializeCertificate } from '../lib/_test_utils';

const ONE_SECOND_AGO = new Date();
ONE_SECOND_AGO.setSeconds(ONE_SECOND_AGO.getSeconds() - 1, 0);

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
      validityStartDate: ONE_SECOND_AGO,
    }),
  );

  const localGatewayKeyPair = await generateRSAKeyPair();
  privateGatewayCert = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: publicGatewayCert,
      issuerPrivateKey: publicGatewayKeyPair.privateKey,
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
  const parcel = new Parcel(
    await peerEndpointCert.calculateSubjectPrivateAddress(),
    endpointPdaCert,
    Buffer.from('hey'),
    {
      creationDate: ONE_SECOND_AGO,
      senderCaCertificateChain: [peerEndpointCert, privateGatewayCert],
    },
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
    expect.toSatisfy((c) => c.isEqual(endpointPdaCert)),
    expect.toSatisfy((c) => c.isEqual(peerEndpointCert)),
    expect.toSatisfy((c) => c.isEqual(privateGatewayCert)),
    expect.toSatisfy((c) => c.isEqual(publicGatewayCert)),
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
    await peerEndpointCert.calculateSubjectPrivateAddress(),
    unauthorizedSenderCertificate,
    Buffer.from('hey'),
    {
      creationDate: ONE_SECOND_AGO,
      senderCaCertificateChain: [peerEndpointCert, privateGatewayCert],
    },
  );

  await expect(parcel.validate([publicGatewayCert])).rejects.toHaveProperty(
    'message',
    'Sender is not authorized: No valid certificate paths found',
  );
});
