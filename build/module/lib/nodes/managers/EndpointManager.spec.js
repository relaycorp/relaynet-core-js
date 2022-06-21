import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { Endpoint } from '../Endpoint';
import { EndpointManager } from './EndpointManager';
const KEY_STORES = new MockKeyStoreSet();
afterEach(() => {
    KEY_STORES.clear();
});
describe('get', () => {
    test('Endpoint instances should be returned', async () => {
        const { privateAddress } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();
        const manager = new EndpointManager(KEY_STORES);
        const endpoint = await manager.get(privateAddress);
        expect(endpoint).toBeInstanceOf(Endpoint);
    });
});
//# sourceMappingURL=EndpointManager.spec.js.map