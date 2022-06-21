"use strict";
/* tslint:disable:max-classes-per-file */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PrivateKeyStore = void 0;
const keys_1 = require("../crypto_wrappers/keys");
const KeyStoreError_1 = require("./KeyStoreError");
const UnknownKeyError_1 = __importDefault(require("./UnknownKeyError"));
class PrivateKeyStore {
    //region Identity keys
    async generateIdentityKeyPair(keyOptions = {}) {
        const keyPair = await this.generateRSAKeyPair(keyOptions);
        const privateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(keyPair.publicKey);
        try {
            await this.saveIdentityKey(privateAddress, keyPair.privateKey);
        }
        catch (err) {
            throw new KeyStoreError_1.KeyStoreError(err, `Failed to save key for ${privateAddress}`);
        }
        return { ...keyPair, privateAddress };
    }
    //endregion
    //region Session keys
    async saveSessionKey(privateKey, keyId, privateAddress, peerPrivateAddress) {
        const keyIdString = keyId.toString('hex');
        const privateKeyDer = await (0, keys_1.derSerializePrivateKey)(privateKey);
        try {
            await this.saveSessionKeySerialized(keyIdString, privateKeyDer, privateAddress, peerPrivateAddress);
        }
        catch (error) {
            throw new KeyStoreError_1.KeyStoreError(error, `Failed to save key ${keyIdString}`);
        }
    }
    /**
     * Return the private component of an initial session key pair.
     *
     * @param keyId The key pair id (typically the serial number)
     * @param privateAddress The private address of the node that owns the key
     * @throws UnknownKeyError when the key does not exist
     * @throws PrivateKeyStoreError when the look up could not be done
     */
    async retrieveUnboundSessionKey(keyId, privateAddress) {
        const keyData = await this.retrieveSessionKeyDataOrThrowError(keyId, privateAddress);
        if (keyData.peerPrivateAddress) {
            throw new UnknownKeyError_1.default(`Key ${keyId.toString('hex')} is bound`);
        }
        return (0, keys_1.derDeserializeECDHPrivateKey)(keyData.keySerialized, 'P-256');
    }
    /**
     * Retrieve private session key, regardless of whether it's an initial key or not.
     *
     * @param keyId The key pair id (typically the serial number)
     * @param privateAddress The private address of the node that owns the key
     * @param peerPrivateAddress The private address of the recipient, in case the key is bound to
     *    a recipient
     * @throws UnknownKeyError when the key does not exist
     * @throws PrivateKeyStoreError when the look up could not be done
     */
    async retrieveSessionKey(keyId, privateAddress, peerPrivateAddress) {
        const keyData = await this.retrieveSessionKeyDataOrThrowError(keyId, privateAddress);
        const keyIdHex = keyId.toString('hex');
        if (keyData.peerPrivateAddress && peerPrivateAddress !== keyData.peerPrivateAddress) {
            throw new UnknownKeyError_1.default(`Session key ${keyIdHex} is bound to another recipient ` +
                `(${keyData.peerPrivateAddress}, not ${peerPrivateAddress})`);
        }
        return (0, keys_1.derDeserializeECDHPrivateKey)(keyData.keySerialized, 'P-256');
    }
    async retrieveSessionKeyDataOrThrowError(keyId, privateAddress) {
        const keyIdHex = keyId.toString('hex');
        let keyData;
        try {
            keyData = await this.retrieveSessionKeyData(keyIdHex);
        }
        catch (error) {
            throw new KeyStoreError_1.KeyStoreError(error, `Failed to retrieve key`);
        }
        if (keyData === null) {
            throw new UnknownKeyError_1.default(`Key ${keyIdHex} does not exist`);
        }
        if (keyData.privateAddress !== privateAddress) {
            throw new UnknownKeyError_1.default('Key is owned by a different node');
        }
        return keyData;
    }
    async generateRSAKeyPair(keyOptions) {
        return (0, keys_1.generateRSAKeyPair)(keyOptions);
    }
}
exports.PrivateKeyStore = PrivateKeyStore;
//# sourceMappingURL=PrivateKeyStore.js.map