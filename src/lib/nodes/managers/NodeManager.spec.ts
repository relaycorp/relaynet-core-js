import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { StubNodeManager } from './_test_utils';
import { derSerializePublicKey } from '../../crypto/keys/serialisation';

const KEY_STORES = new MockKeyStoreSet();
afterEach(() => {
  KEY_STORES.clear();
});

describe('get', () => {
  test('Null should be returned if the private key does not exist', async () => {
    const manager = new StubNodeManager(KEY_STORES);

    await expect(manager.get('non-existing')).resolves.toBeNull();
  });

  test('Node should be returned if private key exists', async () => {
    const { privateKey, id } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();
    const manager = new StubNodeManager(KEY_STORES);

    const gateway = await manager.get(id);

    expect(gateway?.id).toBe(id);
    expect(gateway?.identityKeyPair.privateKey).toBe(privateKey);
  });

  test('Identity public key should be derived from private key', async () => {
    const { publicKey, id } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();
    const manager = new StubNodeManager(KEY_STORES);

    const node = await manager.get(id);

    const publicKeySerialised = await derSerializePublicKey(publicKey);
    await expect(derSerializePublicKey(node!.identityKeyPair.privateKey)).resolves.toMatchObject(
      publicKeySerialised,
    );
  });

  test('Key stores should be passed on', async () => {
    const { id } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();
    const manager = new StubNodeManager(KEY_STORES);

    const node = await manager.get(id);

    expect(node?.keyStores).toBe(KEY_STORES);
  });

  test('Crypto options should be honoured if passed', async () => {
    const { id } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();
    const cryptoOptions = { encryption: { aesKeySize: 256 } };
    const manager = new StubNodeManager(KEY_STORES, cryptoOptions);

    const node = await manager.get(id);

    expect(node?.cryptoOptions).toBe(cryptoOptions);
  });

  test('Custom PrivateGateway subclass should be used if applicable', async () => {
    const customPrivateGateway = {};
    const customPrivateGatewayConstructor = jest.fn().mockReturnValue(customPrivateGateway);
    const manager = new StubNodeManager(KEY_STORES);
    const { privateKey, publicKey, id } =
      await KEY_STORES.privateKeyStore.generateIdentityKeyPair();

    const gateway = await manager.get(id, customPrivateGatewayConstructor);

    expect(gateway).toBe(customPrivateGateway);
    expect(customPrivateGatewayConstructor).toBeCalledWith(
      id,
      { privateKey, publicKey },
      KEY_STORES,
      {},
    );
  });
});
