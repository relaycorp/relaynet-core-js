import { mockSpy } from '../../_test_utils';
import { generateRSAKeyPair, getPrivateAddressFromIdentityKey } from '../../crypto_wrappers/keys';
import { MockKeyStoreSet } from '../../keyStores/testMocks';
import * as privateGatewayModule from '../PrivateGateway';
import { PrivateGatewayManager } from './PrivateGatewayManager';

const MOCK_PRIVATE_GATEWAY = { foo: 'bar' };
const MOCK_PRIVATE_GATEWAY_CLASS = mockSpy(
  jest.spyOn(privateGatewayModule, 'PrivateGateway'),
  () => MOCK_PRIVATE_GATEWAY,
);

let privateAddress: string;
let privateKey: CryptoKey;
beforeAll(async () => {
  const keyPair = await generateRSAKeyPair();
  privateKey = keyPair.privateKey;
  privateAddress = await getPrivateAddressFromIdentityKey(keyPair.privateKey);
});

const KEY_STORES = new MockKeyStoreSet();
afterEach(() => {
  KEY_STORES.clear();
});

describe('get', () => {
  test('Null should be returned if the private key does not exist', async () => {
    const manager = new PrivateGatewayManager(KEY_STORES);

    await expect(manager.get(privateAddress)).resolves.toBeNull();
  });

  test('Node should be returned if private key exists', async () => {
    await KEY_STORES.privateKeyStore.saveIdentityKey(privateKey);
    const manager = new PrivateGatewayManager(KEY_STORES);

    const gateway = await manager.get(privateAddress);

    expect(gateway).toEqual(MOCK_PRIVATE_GATEWAY);
    expect(MOCK_PRIVATE_GATEWAY_CLASS).toBeCalledWith(privateAddress, privateKey, KEY_STORES, {});
  });

  test('Crypto options should be honoured if passed', async () => {
    await KEY_STORES.privateKeyStore.saveIdentityKey(privateKey);
    const cryptoOptions = { encryption: { aesKeySize: 256 } };
    const manager = new PrivateGatewayManager(KEY_STORES, cryptoOptions);

    await manager.get(privateAddress);

    expect(MOCK_PRIVATE_GATEWAY_CLASS).toBeCalledWith(
      expect.anything(),
      expect.anything(),
      expect.anything(),
      cryptoOptions,
    );
  });
});
