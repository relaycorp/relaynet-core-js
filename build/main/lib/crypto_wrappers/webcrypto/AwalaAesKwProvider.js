"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AwalaAesKwProvider = void 0;
const aes_kw_1 = require("@stablelib/aes-kw");
const webcrypto_core_1 = require("webcrypto-core");
/**
 * AES-KW provider that uses pure JavaScript for encryption and decryption.
 */
class AwalaAesKwProvider extends webcrypto_core_1.AesKwProvider {
    constructor(originalProvider) {
        super();
        this.originalProvider = originalProvider;
    }
    async onGenerateKey(algorithm, extractable, 
    // tslint:disable-next-line:readonly-array
    keyUsages) {
        return this.originalProvider.onGenerateKey(algorithm, extractable, keyUsages);
    }
    async onExportKey(format, key) {
        return this.originalProvider.onExportKey(format, key);
    }
    async onImportKey(format, keyData, algorithm, extractable, 
    // tslint:disable-next-line:readonly-array
    keyUsages) {
        return this.originalProvider.onImportKey(format, keyData, algorithm, extractable, keyUsages);
    }
    async onEncrypt(_algorithm, key, data) {
        const aesKw = await this.makeAesKw(key);
        return aesKw.wrapKey(new Uint8Array(data));
    }
    async onDecrypt(_algorithm, key, data) {
        const aesKw = await this.makeAesKw(key);
        return typedArrayToBuffer(aesKw.unwrapKey(new Uint8Array(data)));
    }
    async makeAesKw(key) {
        const keyExported = (await this.onExportKey('raw', key));
        return new aes_kw_1.AESKW(new Uint8Array(keyExported));
    }
}
exports.AwalaAesKwProvider = AwalaAesKwProvider;
function typedArrayToBuffer(array) {
    return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset);
}
//# sourceMappingURL=AwalaAesKwProvider.js.map