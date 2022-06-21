export class NodeManager {
    keyStores;
    cryptoOptions;
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
//# sourceMappingURL=NodeManager.js.map