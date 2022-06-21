"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const testMocks_1 = require("../../keyStores/testMocks");
const Endpoint_1 = require("../Endpoint");
const EndpointManager_1 = require("./EndpointManager");
const KEY_STORES = new testMocks_1.MockKeyStoreSet();
afterEach(() => {
    KEY_STORES.clear();
});
describe('get', () => {
    test('Endpoint instances should be returned', async () => {
        const { privateAddress } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();
        const manager = new EndpointManager_1.EndpointManager(KEY_STORES);
        const endpoint = await manager.get(privateAddress);
        expect(endpoint).toBeInstanceOf(Endpoint_1.Endpoint);
    });
});
//# sourceMappingURL=EndpointManager.spec.js.map