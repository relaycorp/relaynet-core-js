import { SessionEnvelopedData } from '../../crypto_wrappers/cms/envelopedData';
import { getPrivateAddressFromIdentityKey } from '../../crypto_wrappers/keys';
import { NodeError } from '../errors';
export class Channel {
    nodePrivateKey;
    nodeDeliveryAuth;
    peerPrivateAddress;
    peerPublicKey;
    keyStores;
    cryptoOptions;
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
            throw new NodeError(`Could not find session key for peer ${this.peerPrivateAddress}`);
        }
        const { envelopedData, dhKeyId, dhPrivateKey } = await SessionEnvelopedData.encrypt(payload instanceof ArrayBuffer ? payload : payload.serialize(), recipientSessionKey, this.cryptoOptions.encryption);
        await this.keyStores.privateKeyStore.saveSessionKey(dhPrivateKey, Buffer.from(dhKeyId), await this.getNodePrivateAddress(), this.peerPrivateAddress);
        return envelopedData.serialize();
    }
    async getNodePrivateAddress() {
        return getPrivateAddressFromIdentityKey(this.nodePrivateKey);
    }
}
//# sourceMappingURL=Channel.js.map