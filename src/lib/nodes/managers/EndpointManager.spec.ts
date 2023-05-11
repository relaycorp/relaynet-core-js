import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { EndpointManager } from './EndpointManager';
import { StubNode } from '../_test_utils';

const KEY_STORES = new MockKeyStoreSet();
afterEach(() => {
  KEY_STORES.clear();
});

describe('get', () => {
  test('Endpoint instances should be returned', async () => {
    const { id } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();
    const manager = new StubEndpointManager(KEY_STORES);

    const endpoint = await manager.get(id);

    expect(endpoint).toBeInstanceOf(StubNode);
  });
});

class StubEndpointManager extends EndpointManager<undefined> {
  protected readonly defaultNodeConstructor = StubNode;
}
