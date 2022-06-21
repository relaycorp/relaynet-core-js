"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Channel = void 0;
const envelopedData_1 = require("../../crypto_wrappers/cms/envelopedData");
const keys_1 = require("../../crypto_wrappers/keys");
const errors_1 = require("../errors");
class Channel {
    // noinspection TypeScriptAbstractClassConstructorCanBeMadeProtected
    constructor(nodePrivateKey, nodeDeliveryAuth, peerPrivateAddress, peerPublicKey, keyStores, cryptoOptions = {}) {
        this.nodePrivateKey = nodePrivateKey;
        this.nodeDeliveryAuth = nodeDeliveryAuth;
        this.peerPrivateAddress = peerPrivateAddress;
        this.peerPublicKey = peerPublicKey;
        this.keyStores = keyStores;
        this.cryptoOptions = cryptoOptions;
    }
    /**
     * Encrypt and serialize the `payload`.
     *
     * @param payload
     *
     * Also store the new ephemeral session key.
     */
    async wrapMessagePayload(payload) {
        const recipientSessionKey = await this.keyStores.publicKeyStore.retrieveLastSessionKey(this.peerPrivateAddress);
        if (!recipientSessionKey) {
            throw new errors_1.NodeError(`Could not find session key for peer ${this.peerPrivateAddress}`);
        }
        const { envelopedData, dhKeyId, dhPrivateKey } = await envelopedData_1.SessionEnvelopedData.encrypt(payload instanceof ArrayBuffer ? payload : payload.serialize(), recipientSessionKey, this.cryptoOptions.encryption);
        await this.keyStores.privateKeyStore.saveSessionKey(dhPrivateKey, Buffer.from(dhKeyId), await this.getNodePrivateAddress(), this.peerPrivateAddress);
        return envelopedData.serialize();
    }
    async getNodePrivateAddress() {
        return (0, keys_1.getPrivateAddressFromIdentityKey)(this.nodePrivateKey);
    }
}
exports.Channel = Channel;
//# sourceMappingURL=Channel.js.map