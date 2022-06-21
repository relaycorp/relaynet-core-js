"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NodeManager = void 0;
class NodeManager {
    constructor(keyStores, cryptoOptions = {}) {
        this.keyStores = keyStores;
        this.cryptoOptions = cryptoOptions;
    }
    async get(privateAddress, nodeConstructor) {
        const nodePrivateKey = await this.keyStores.privateKeyStore.retrieveIdentityKey(privateAddress);
        if (!nodePrivateKey) {
            return null;
        }
        const constructor = nodeConstructor ?? this.defaultNodeConstructor;
        return new constructor(privateAddress, nodePrivateKey, this.keyStores, this.cryptoOptions);
    }
}
exports.NodeManager = NodeManager;
//# sourceMappingURL=NodeManager.js.map