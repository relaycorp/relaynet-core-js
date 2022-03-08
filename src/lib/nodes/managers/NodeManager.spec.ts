import {
  derSerializePrivateKey,
  derSerializePublicKey,
  generateRSAKeyPair,
  getPrivateAddressFromIdentityKey,
} from '../../crypto_wrappers/keys';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import {
  MockCertificateStore,
  MockPrivateKeyStore,
  MockPublicKeyStore,
} from '../../keyStores/testMocks';
import { StubNode } from '../_test_utils';
import { NodeManager } from './NodeManager';

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
});

describe('getPrivate', () => {
  let nodePrivateKey: CryptoKey;
  let nodePrivateAddress: string;
  beforeAll(async () => {
    const recipientKeyPair = await generateRSAKeyPair();
    nodePrivateKey = recipientKeyPair.privateKey;
    nodePrivateAddress = await getPrivateAddressFromIdentityKey(nodePrivateKey);
  });

  test('Null should be returned if the private key does not exist', async () => {
    const manager = new StubNodeManager(KEY_STORES);

    await expect(manager.getPrivate(nodePrivateAddress)).resolves.toBeNull();
  });

  test('Node should be returned if private key exists', async () => {
    await PRIVATE_KEY_STORE.saveIdentityKey(nodePrivateKey);
    const manager = new StubNodeManager(KEY_STORES);

    const node = await manager.getPrivate(nodePrivateAddress);

    await expect(derSerializePrivateKey(node!.getPrivateKey())).resolves.toEqual(
      await derSerializePrivateKey(nodePrivateKey),
    );
    expect(node?.getKeyStores()).toEqual(KEY_STORES);
  });

  test('Crypto options should be honoured if passed', async () => {
    await PRIVATE_KEY_STORE.saveIdentityKey(nodePrivateKey);
    const cryptoOptions = { encryption: { aesKeySize: 256 } };
    const manager = new StubNodeManager(KEY_STORES, cryptoOptions);

    const node = await manager.getPrivate(nodePrivateAddress);

    expect(node?.cryptoOptions).toEqual(cryptoOptions);
  });
});

describe('generateSessionKey', () => {
  test('Key should not be bound to any peer by default', async () => {
    const manager = new StubNodeManager(KEY_STORES);

    const sessionKey = await manager.generateSessionKey();

    await expect(
      derSerializePublicKey(await PRIVATE_KEY_STORE.retrieveUnboundSessionKey(sessionKey.keyId)),
    ).resolves.toEqual(await derSerializePublicKey(sessionKey.publicKey));
  });

  test('Key should be bound to a peer if explicitly set', async () => {
    const manager = new StubNodeManager(KEY_STORES);
    const peerPrivateAddress = '0deadbeef';

    const sessionKey = await manager.generateSessionKey(peerPrivateAddress);

    await expect(
      derSerializePublicKey(
        await PRIVATE_KEY_STORE.retrieveSessionKey(sessionKey.keyId, peerPrivateAddress),
      ),
    ).resolves.toEqual(await derSerializePublicKey(sessionKey.publicKey));
  });
});

class StubNodeManager extends NodeManager<StubNode> {
  readonly nodeClass = StubNode;
}
