"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PublicKeyStore = void 0;
const keys_1 = require("../crypto_wrappers/keys");
const KeyStoreError_1 = require("./KeyStoreError");
class PublicKeyStore {
    //region Identity keys
    async saveIdentityKey(key) {
        const peerPrivateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(key);
        const keySerialized = await (0, keys_1.derSerializePublicKey)(key);
        await this.saveIdentityKeySerialized(keySerialized, peerPrivateAddress);
    }
    async retrieveIdentityKey(peerPrivateAddress) {
        const keySerialized = await this.retrieveIdentityKeySerialized(peerPrivateAddress);
        return keySerialized ? (0, keys_1.derDeserializeRSAPublicKey)(keySerialized) : null;
    }
    //endregion
    //region Session keys
    async saveSessionKey(key, peerPrivateAddress, creationTime) {
        const priorKeyData = await this.fetchSessionKeyDataOrWrapError(peerPrivateAddress);
        if (priorKeyData && creationTime <= priorKeyData.publicKeyCreationTime) {
            return;
        }
        const keyData = {
            publicKeyCreationTime: creationTime,
            publicKeyDer: await (0, keys_1.derSerializePublicKey)(key.publicKey),
            publicKeyId: key.keyId,
        };
        try {
            await this.saveSessionKeyData(keyData, peerPrivateAddress);
        }
        catch (error) {
            throw new KeyStoreError_1.KeyStoreError(error, 'Failed to save public session key');
        }
    }
    async retrieveLastSessionKey(peerPrivateAddress) {
        const keyData = await this.fetchSessionKeyDataOrWrapError(peerPrivateAddress);
        if (!keyData) {
            return null;
        }
        const publicKey = await (0, keys_1.derDeserializeECDHPublicKey)(keyData.publicKeyDer);
        return { publicKey, keyId: keyData.publicKeyId };
    }
    async fetchSessionKeyDataOrWrapError(peerPrivateAddress) {
        try {
            return await this.retrieveSessionKeyData(peerPrivateAddress);
        }
        catch (error) {
            throw new KeyStoreError_1.KeyStoreError(error, 'Failed to retrieve key');
        }
    }
}
exports.PublicKeyStore = PublicKeyStore;
//# sourceMappingURL=PublicKeyStore.js.map