"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AwalaCrypto = void 0;
const webcrypto_1 = require("@peculiar/webcrypto");
const crypto_1 = require("crypto");
const AwalaAesKwProvider_1 = require("./AwalaAesKwProvider");
class AwalaCrypto extends webcrypto_1.Crypto {
    constructor() {
        super();
        const doesNodejsSupportAesKw = (0, crypto_1.getCiphers)().includes('id-aes128-wrap');
        if (!doesNodejsSupportAesKw) {
            // This must be running on Electron, so let's use a pure JavaScript implementation of AES-KW:
            // https://github.com/relaycorp/relaynet-core-js/issues/367
            const providers = this.subtle.providers;
            const nodejsAesKwProvider = providers.get('AES-KW');
            providers.set(new AwalaAesKwProvider_1.AwalaAesKwProvider(nodejsAesKwProvider));
        }
    }
}
exports.AwalaCrypto = AwalaCrypto;
//# sourceMappingURL=AwalaCrypto.js.map