import { getRSAPublicKeyFromPrivate } from '../crypto_wrappers/keys';
import { SessionKeyPair } from '../SessionKeyPair';
export class Node {
    privateAddress;
    identityPrivateKey;
    keyStores;
    cryptoOptions;
    constructor(privateAddress, identityPrivateKey, keyStores, cryptoOptions) {
        this.privateAddress = privateAddress;
        this.identityPrivateKey = identityPrivateKey;
        this.keyStores = keyStores;
        this.cryptoOptions = cryptoOptions;
    }
    async getIdentityPublicKey() {
        return getRSAPublicKeyFromPrivate(this.identityPrivateKey);
    }
    /**
     * Generate and store a new session key.
     *
     * @param peerPrivateAddress The peer to bind the key to, unless it's an initial key
     */
    async generateSessionKey(peerPrivateAddress) {
        const { sessionKey, privateKey } = await SessionKeyPair.generate();
        await this.keyStores.privateKeyStore.saveSessionKey(privateKey, sessionKey.keyId, this.privateAddress, peerPrivateAddress);
        return sessionKey;
    }
    async getGSCSigner(peerPrivateAddress, signerClass) {
        const path = await this.keyStores.certificateStore.retrieveLatest(this.privateAddress, peerPrivateAddress);
        if (!path) {
            return null;
        }
        return new signerClass(path.leafCertificate, this.identityPrivateKey);
    }
    /**
     * Decrypt and return the payload in the `message`.
     *
     * Also store the session key from the sender.
     *
     * @param message
     */
    async unwrapMessagePayload(message) {
        const unwrapResult = await message.unwrapPayload(this.keyStores.privateKeyStore, this.privateAddress);
        await this.keyStores.publicKeyStore.saveSessionKey(unwrapResult.senderSessionKey, await message.senderCertificate.calculateSubjectPrivateAddress(), message.creationDate);
        return unwrapResult.payload;
    }
}
//# sourceMappingURL=Node.js.map