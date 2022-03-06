import { derSerializePublicKey, generateRSAKeyPair } from '../../crypto_wrappers/keys';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import {
  MockCertificateStore,
  MockPrivateKeyStore,
  MockPublicKeyStore,
} from '../../keyStores/testMocks';
import { NodeManager } from './NodeManager';

let nodePrivateKey: CryptoKey;
beforeAll(async () => {
  const recipientKeyPair = await generateRSAKeyPair();
  nodePrivateKey = recipientKeyPair.privateKey;
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
