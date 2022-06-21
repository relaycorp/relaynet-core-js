"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const testMocks_1 = require("../../keyStores/testMocks");
const PrivateGateway_1 = require("../PrivateGateway");
const PrivateGatewayManager_1 = require("./PrivateGatewayManager");
const KEY_STORES = new testMocks_1.MockKeyStoreSet();
afterEach(() => {
    KEY_STORES.clear();
});
describe('get', () => {
    test('PrivateGateway instances should be returned', async () => {
        const { privateAddress } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();
        const manager = new PrivateGatewayManager_1.PrivateGatewayManager(KEY_STORES);
        const gateway = await manager.get(privateAddress);
        expect(gateway).toBeInstanceOf(PrivateGateway_1.PrivateGateway);
    });
});
//# sourceMappingURL=PrivateGatewayManager.spec.js.map