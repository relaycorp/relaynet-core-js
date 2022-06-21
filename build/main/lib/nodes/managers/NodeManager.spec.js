"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const _test_utils_1 = require("../../_test_utils");
const testMocks_1 = require("../../keyStores/testMocks");
const nodeTestUtils = __importStar(require("../_test_utils"));
const _test_utils_2 = require("./_test_utils");
const MOCK_NODE_CLASS = (0, _test_utils_1.mockSpy)(jest.spyOn(nodeTestUtils, 'StubNode'));
const KEY_STORES = new testMocks_1.MockKeyStoreSet();
afterEach(() => {
    KEY_STORES.clear();
});
describe('get', () => {
    test('Null should be returned if the private key does not exist', async () => {
        const manager = new _test_utils_2.StubNodeManager(KEY_STORES);
        await expect(manager.get('non-existing')).resolves.toBeNull();
    });
    test('Node should be returned if private key exists', async () => {
        const { privateKey, privateAddress } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();
        const manager = new _test_utils_2.StubNodeManager(KEY_STORES);
        const gateway = await manager.get(privateAddress);
        expect(MOCK_NODE_CLASS).toBeCalledWith(privateAddress, privateKey, KEY_STORES, {});
        expect(gateway).toEqual(MOCK_NODE_CLASS.mock.instances[0]);
    });
    test('Key stores should be passed on', async () => {
        const { privateAddress } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();
        const manager = new _test_utils_2.StubNodeManager(KEY_STORES);
        await manager.get(privateAddress);
        expect(MOCK_NODE_CLASS).toBeCalledWith(expect.anything(), expect.anything(), KEY_STORES, expect.anything());
    });
    test('Crypto options should be honoured if passed', async () => {
        const { privateAddress } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();
        const cryptoOptions = { encryption: { aesKeySize: 256 } };
        const manager = new _test_utils_2.StubNodeManager(KEY_STORES, cryptoOptions);
        await manager.get(privateAddress);
        expect(MOCK_NODE_CLASS).toBeCalledWith(expect.anything(), expect.anything(), expect.anything(), cryptoOptions);
    });
    test('Custom PrivateGateway subclass should be used if applicable', async () => {
        const customPrivateGateway = {};
        const customPrivateGatewayConstructor = jest.fn().mockReturnValue(customPrivateGateway);
        const manager = new _test_utils_2.StubNodeManager(KEY_STORES);
        const { privateKey, privateAddress } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();
        const gateway = await manager.get(privateAddress, customPrivateGatewayConstructor);
        expect(gateway).toBe(customPrivateGateway);
        expect(customPrivateGatewayConstructor).toBeCalledWith(privateAddress, privateKey, KEY_STORES, {});
    });
});
//# sourceMappingURL=NodeManager.spec.js.map