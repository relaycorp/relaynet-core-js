import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { PrivateGateway } from '../PrivateGateway';
import { PrivateGatewayManager } from './PrivateGatewayManager';

const KEY_STORES = new MockKeyStoreSet();
afterEach(() => {
  KEY_STORES.clear();
});

describe('get', () => {
  test('PrivateGateway instances should be returned', async () => {
    const { id } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();
    const manager = new PrivateGatewayManager(KEY_STORES);

    const gateway = await manager.get(id);

    expect(gateway).toBeInstanceOf(PrivateGateway);
  });
});
