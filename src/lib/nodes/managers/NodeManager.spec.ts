import { derSerializePublicKey } from '../../crypto_wrappers/keys';
import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { NodeManager } from './NodeManager';

const KEY_STORES = new MockKeyStoreSet();
beforeEach(async () => {
  KEY_STORES.clear();
});

describe('generateSessionKey', () => {
  test('Key should not be bound to any peer by default', async () => {
    const manager = new StubNodeManager(KEY_STORES);

    const sessionKey = await manager.generateSessionKey();

    await expect(
      derSerializePublicKey(
        await KEY_STORES.privateKeyStore.retrieveUnboundSessionKey(sessionKey.keyId),
      ),
    ).resolves.toEqual(await derSerializePublicKey(sessionKey.publicKey));
  });

  test('Key should be bound to a peer if explicitly set', async () => {
    const manager = new StubNodeManager(KEY_STORES);
    const peerPrivateAddress = '0deadbeef';

    const sessionKey = await manager.generateSessionKey(peerPrivateAddress);

    await expect(
      derSerializePublicKey(
        await KEY_STORES.privateKeyStore.retrieveSessionKey(sessionKey.keyId, peerPrivateAddress),
      ),
    ).resolves.toEqual(await derSerializePublicKey(sessionKey.publicKey));
  });
});

class StubNodeManager extends NodeManager {}
