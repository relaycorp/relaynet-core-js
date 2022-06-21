"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionKeyPair = void 0;
const _utils_1 = require("./crypto_wrappers/_utils");
const keys_1 = require("./crypto_wrappers/keys");
class SessionKeyPair {
    constructor(sessionKey, privateKey) {
        this.sessionKey = sessionKey;
        this.privateKey = privateKey;
    }
    /**
     * Generate a new session key pair.
     */
    static async generate() {
        const keyPair = await (0, keys_1.generateECDHKeyPair)();
        const keyId = await (0, _utils_1.generateRandom64BitValue)();
        const sessionKey = { keyId: Buffer.from(keyId), publicKey: keyPair.publicKey };
        return new SessionKeyPair(sessionKey, keyPair.privateKey);
    }
}
exports.SessionKeyPair = SessionKeyPair;
//# sourceMappingURL=SessionKeyPair.js.map