"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const webcrypto_1 = require("@peculiar/webcrypto");
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const webcrypto_core_1 = require("webcrypto-core");
const _test_utils_1 = require("../../_test_utils");
const AwalaAesKwProvider_1 = require("./AwalaAesKwProvider");
const nodejsCrypto = new webcrypto_1.Crypto();
const nodejsAesKwProvider = nodejsCrypto.subtle.providers.get('AES-KW');
const algorithm = { name: 'AES-KW', length: 128 };
// tslint:disable-next-line:readonly-array
const keyUsages = ['wrapKey', 'unwrapKey'];
let cryptoKey;
beforeAll(async () => {
    cryptoKey = (await nodejsCrypto.subtle.generateKey(algorithm, true, keyUsages));
});
const unwrappedKeySerialized = (0, buffer_to_arraybuffer_1.default)(Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex'));
describe('onGenerateKey', () => {
    test('Method should proxy original provider', async () => {
        const originalProvider = new MockAesKwProvider();
        originalProvider.onGenerateKey.mockResolvedValue(cryptoKey);
        const provider = new AwalaAesKwProvider_1.AwalaAesKwProvider(originalProvider);
        const generatedKey = await provider.onGenerateKey(algorithm, true, keyUsages);
        expect(generatedKey).toBe(cryptoKey);
        expect(originalProvider.onGenerateKey).toBeCalledWith(algorithm, true, keyUsages);
    });
});
describe('onExportKey', () => {
    test('Method should proxy original provider', async () => {
        const cryptoKeySerialized = (0, _test_utils_1.arrayBufferFrom)('this is the key, serialized');
        const originalProvider = new MockAesKwProvider();
        originalProvider.onExportKey.mockResolvedValue(cryptoKeySerialized);
        const provider = new AwalaAesKwProvider_1.AwalaAesKwProvider(originalProvider);
        const keyFormat = 'raw';
        const exportedKey = await provider.onExportKey(keyFormat, cryptoKey);
        expect(exportedKey).toBe(cryptoKeySerialized);
        expect(originalProvider.onExportKey).toBeCalledWith(keyFormat, cryptoKey);
    });
});
describe('onImportKey', () => {
    test('Method should proxy original provider', async () => {
        const originalProvider = new MockAesKwProvider();
        originalProvider.onImportKey.mockResolvedValue(cryptoKey);
        const provider = new AwalaAesKwProvider_1.AwalaAesKwProvider(originalProvider);
        const keyFormat = 'raw';
        const cryptoKeySerialized = (0, _test_utils_1.arrayBufferFrom)('this is the key, serialized');
        const exportedKey = await provider.onImportKey(keyFormat, cryptoKeySerialized, algorithm, true, keyUsages);
        expect(exportedKey).toBe(cryptoKey);
        expect(originalProvider.onImportKey).toBeCalledWith(keyFormat, cryptoKeySerialized, algorithm, true, keyUsages);
    });
});
describe('onEncrypt', () => {
    test('Ciphertext should be decryptable with Node.js', async () => {
        const provider = new AwalaAesKwProvider_1.AwalaAesKwProvider(nodejsAesKwProvider);
        const wrappedKey = await provider.onEncrypt(algorithm, cryptoKey, unwrappedKeySerialized);
        const unwrappedKey = await nodejsCrypto.subtle.unwrapKey('raw', wrappedKey, cryptoKey, algorithm, algorithm, true, keyUsages);
        await expect(nodejsAesKwProvider.exportKey('raw', unwrappedKey)).resolves.toEqual(unwrappedKeySerialized);
    });
});
describe('onDecrypt', () => {
    test('Ciphertext produced with Node.js should be decryptable', async () => {
        const provider = new AwalaAesKwProvider_1.AwalaAesKwProvider(nodejsAesKwProvider);
        const nodejsWrappedKey = await nodejsAesKwProvider.onEncrypt(algorithm, cryptoKey, unwrappedKeySerialized);
        const unwrappedKey = await provider.onDecrypt(algorithm, cryptoKey, nodejsWrappedKey);
        expect(unwrappedKey).toEqual(unwrappedKeySerialized);
    });
});
class MockAesKwProvider extends webcrypto_core_1.AesKwProvider {
    constructor() {
        super(...arguments);
        this.onGenerateKey = jest.fn();
        this.onExportKey = jest.fn();
        this.onImportKey = jest.fn();
    }
}
//# sourceMappingURL=AwalaAesKwProvider.spec.js.map