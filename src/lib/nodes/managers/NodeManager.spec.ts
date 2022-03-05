import { addDays, setMilliseconds } from 'date-fns';

import { derSerializePublicKey, generateRSAKeyPair } from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { CertificateScope } from '../../keyStores/CertificateStore';
import { MockCertificateStore } from '../../keyStores/CertificateStore.spec';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { MockPrivateKeyStore, MockPublicKeyStore } from '../../keyStores/testMocks';
import { issueGatewayCertificate } from '../../pki';
import { NodeManager } from './NodeManager';

const TOMORROW = setMilliseconds(addDays(new Date(), 1), 0);

let nodePrivateKey: CryptoKey;
let nodeCertificate: Certificate;
beforeAll(async () => {
  const recipientKeyPair = await generateRSAKeyPair();
  nodePrivateKey = recipientKeyPair.privateKey;

  nodeCertificate = await issueGatewayCertificate({
    issuerPrivateKey: recipientKeyPair.privateKey,
    subjectPublicKey: recipientKeyPair.publicKey,
    validityEndDate: TOMORROW,
  });
});

const PRIVATE_KEY_STORE = new MockPrivateKeyStore();
const PUBLIC_KEY_STORE = new MockPublicKeyStore();
const CERTIFICATE_STORE = new MockCertificateStore();
const KEY_STORES: KeyStoreSet = {
  privateKeyStore: PRIVATE_KEY_STORE,
  publicKeyStore: PUBLIC_KEY_STORE,
  certificateStore: CERTIFICATE_STORE,
};
beforeEach(async () => {
  PRIVATE_KEY_STORE.clear();
  PUBLIC_KEY_STORE.clear();
  CERTIFICATE_STORE.clear();

  await PRIVATE_KEY_STORE.saveIdentityKey(nodePrivateKey);
  await CERTIFICATE_STORE.save(nodeCertificate, CertificateScope.PDA);
});

describe('getNode', () => {
  test.todo('Node should be of the correct type');

  test.todo('Certificate and private key should be passed on');

  test.todo('Private and public key stores should be passed on');

  test.todo('Encryption options should be passed on');
});

describe('generateSessionKey', () => {
  test('Key should not be bound to any peer by default', async () => {
    const node = new StubNodeManager(KEY_STORES);

    const sessionKey = await node.generateSessionKey();

    await expect(
      derSerializePublicKey(await PRIVATE_KEY_STORE.retrieveUnboundSessionKey(sessionKey.keyId)),
    ).resolves.toEqual(await derSerializePublicKey(sessionKey.publicKey));
  });

  test('Key should be bound to a peer if explicitly set', async () => {
    const node = new StubNodeManager(KEY_STORES);
    const peerPrivateAddress = '0deadbeef';

    const sessionKey = await node.generateSessionKey(peerPrivateAddress);

    await expect(
      derSerializePublicKey(
        await PRIVATE_KEY_STORE.retrieveSessionKey(sessionKey.keyId, peerPrivateAddress),
      ),
    ).resolves.toEqual(await derSerializePublicKey(sessionKey.publicKey));
  });
});

class StubNodeManager extends NodeManager {}
