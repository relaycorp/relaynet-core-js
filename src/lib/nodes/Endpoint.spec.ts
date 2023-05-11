import { addDays } from 'date-fns';

import { CertificationPath } from '../pki/CertificationPath';
import { MockKeyStoreSet } from '../keyStores/testMocks';
import { issueEndpointCertificate, issueGatewayCertificate } from '../pki/issuance';
import { getIdFromIdentityKey } from '../crypto/keys/digest';
import { generateRSAKeyPair } from '../crypto/keys/generation';
import { Certificate } from '../crypto/x509/Certificate';
import { reSerializeCertificate } from '../_test_utils';
import { PrivateEndpointConnParams } from './PrivateEndpointConnParams';
import { SessionKeyPair } from '../SessionKeyPair';
import { derSerializePublicKey } from '../crypto/keys/serialisation';
import { SessionPublicKeyData } from '../keyStores/PublicKeyStore';
import { InvalidNodeConnectionParams } from './errors';
import { Peer } from './peer';
import { StubEndpoint } from './_test_utils';

const INTERNET_ADDRESS = 'example.com';

let peerId: string;
let peerIdentityKeyPair: CryptoKeyPair;
let peerCertificate: Certificate;
beforeAll(async () => {
  peerIdentityKeyPair = await generateRSAKeyPair();
  peerId = await getIdFromIdentityKey(peerIdentityKeyPair.publicKey);
  peerCertificate = await issueEndpointCertificate({
    issuerPrivateKey: peerIdentityKeyPair.privateKey,
    subjectPublicKey: peerIdentityKeyPair.publicKey,
    validityEndDate: addDays(new Date(), 1),
  });
});

let nodeId: string;
let nodeKeyPair: CryptoKeyPair;
let nodeCertificate: Certificate;
beforeAll(async () => {
  nodeKeyPair = await generateRSAKeyPair();
  nodeCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: peerCertificate,
      issuerPrivateKey: peerIdentityKeyPair.privateKey,
      subjectPublicKey: nodeKeyPair.publicKey,
      validityEndDate: peerCertificate.expiryDate,
    }),
  );
  nodeId = await getIdFromIdentityKey(nodeKeyPair.publicKey);
});

const KEY_STORES = new MockKeyStoreSet();
beforeEach(async () => {
  KEY_STORES.clear();
});

describe('savePrivateEndpointChannel', () => {
  let connectionParams: PrivateEndpointConnParams;
  beforeAll(async () => {
    const deliveryAuth = new CertificationPath(nodeCertificate, [peerCertificate]);
    connectionParams = new PrivateEndpointConnParams(
      peerIdentityKeyPair.publicKey,
      INTERNET_ADDRESS,
      deliveryAuth,
    );
  });

  test('Delivery authorization should be refused if granted to other node', async () => {
    const node = new StubEndpoint(`not-${nodeId}`, nodeKeyPair, KEY_STORES, {});

    await expect(node.savePrivateEndpointChannel(connectionParams)).rejects.toThrowWithMessage(
      InvalidNodeConnectionParams,
      `Delivery authorization was granted to another node (${nodeId})`,
    );
  });

  test('Delivery authorization should be stored if valid', async () => {
    const node = new StubEndpoint(nodeId, nodeKeyPair, KEY_STORES, {});

    await node.savePrivateEndpointChannel(connectionParams);

    const deliveryAuthorisations = await KEY_STORES.certificateStore.retrieveAll(nodeId, peerId);
    expect(deliveryAuthorisations).toHaveLength(1);
    const [deliveryAuthorisation] = deliveryAuthorisations;
    expect(Buffer.from(deliveryAuthorisation.serialize())).toStrictEqual(
      Buffer.from(connectionParams.deliveryAuth.serialize()),
    );
  });

  test('Identity public key of peer should be stored', async () => {
    const node = new StubEndpoint(nodeId, nodeKeyPair, KEY_STORES, {});

    await node.savePrivateEndpointChannel(connectionParams);

    expect(KEY_STORES.publicKeyStore.identityKeys).toHaveProperty(
      peerId,
      await derSerializePublicKey(peerIdentityKeyPair.publicKey),
    );
  });

  test('Session public key of peer should be stored if set', async () => {
    const node = new StubEndpoint(nodeId, nodeKeyPair, KEY_STORES, {});
    const dateBeforeSave = new Date();
    const { sessionKey } = await SessionKeyPair.generate();
    const paramsWithSessionKey = new PrivateEndpointConnParams(
      connectionParams.identityKey,
      connectionParams.internetGatewayAddress,
      connectionParams.deliveryAuth,
      sessionKey,
    );

    await node.savePrivateEndpointChannel(paramsWithSessionKey);

    expect(KEY_STORES.publicKeyStore.sessionKeys).toHaveProperty(
      peerId,
      expect.objectContaining<SessionPublicKeyData>({
        publicKeyId: sessionKey.keyId,
        publicKeyDer: await derSerializePublicKey(sessionKey.publicKey),
        publicKeyCreationTime: expect.toSatisfy<Date>(
          (date) => date <= new Date() && dateBeforeSave <= date,
        ),
      }),
    );
  });

  test('Resulting channel should be output', async () => {
    const node = new StubEndpoint(nodeId, nodeKeyPair, KEY_STORES, {});

    const channel = await node.savePrivateEndpointChannel(connectionParams);

    expect(channel.node).toBe(node);
    expect(channel.peer).toMatchObject<Peer<string>>({
      id: peerId,
      identityPublicKey: peerIdentityKeyPair.publicKey,
      internetAddress: INTERNET_ADDRESS,
    });
    expect(channel.deliveryAuthPath).toBe(connectionParams.deliveryAuth);
  });

  test('Key store should be propagated', async () => {
    const node = new StubEndpoint(nodeId, nodeKeyPair, KEY_STORES, {});

    const channel = await node.savePrivateEndpointChannel(connectionParams);

    expect(channel.keyStores).toBe(KEY_STORES);
  });

  test('Crypto options should be propagated', async () => {
    const node = new StubEndpoint(nodeId, nodeKeyPair, KEY_STORES, {
      encryption: { aesKeySize: 128 },
    });

    const channel = await node.savePrivateEndpointChannel(connectionParams);

    expect(channel.cryptoOptions).toBe(node.cryptoOptions);
  });
});
