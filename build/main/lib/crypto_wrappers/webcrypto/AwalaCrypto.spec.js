"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const _test_utils_1 = require("../../_test_utils");
const AwalaAesKwProvider_1 = require("./AwalaAesKwProvider");
const AwalaCrypto_1 = require("./AwalaCrypto");
jest.mock('crypto');
const CIPHERS = [
    'aes-128-cbc',
    'aes-128-cfb',
    'aes-128-ctr',
    'aes-128-ecb',
    'aes-128-gcm',
    'aes-128-ofb',
];
describe('Constructor', () => {
    test("Pure JavaScript AES-KW provider should be used if Node doesn't support cipher", () => {
        (0, _test_utils_1.getMockInstance)(crypto_1.getCiphers).mockReturnValue(CIPHERS);
        const crypto = new AwalaCrypto_1.AwalaCrypto();
        const aesKwProvider = crypto.subtle.providers.get('AES-KW');
        expect(aesKwProvider).toBeInstanceOf(AwalaAesKwProvider_1.AwalaAesKwProvider);
    });
    test('Node.js AES-KW provider should be used if Node supports cipher', () => {
        (0, _test_utils_1.getMockInstance)(crypto_1.getCiphers).mockReturnValue([...CIPHERS, 'id-aes128-wrap']);
        const crypto = new AwalaCrypto_1.AwalaCrypto();
        const aesKwProvider = crypto.subtle.providers.get('AES-KW');
        expect(aesKwProvider).toBeTruthy();
        expect(aesKwProvider).not.toBeInstanceOf(AwalaAesKwProvider_1.AwalaAesKwProvider);
    });
});
//# sourceMappingURL=AwalaCrypto.spec.js.map