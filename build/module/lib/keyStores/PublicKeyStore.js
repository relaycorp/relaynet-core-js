import { derDeserializeECDHPublicKey, derDeserializeRSAPublicKey, derSerializePublicKey, getPrivateAddressFromIdentityKey, } from '../crypto_wrappers/keys';
import { KeyStoreError } from './KeyStoreError';
export class PublicKeyStore {
    //region Identity keys
    async saveIdentityKey(key) {
        const peerPrivateAddress = await getPrivateAddressFromIdentityKey(key);
        const keySerialized = await derSerializePublicKey(key);
        await this.saveIdentityKeySerialized(keySerialized, peerPrivateAddress);
    }
    async retrieveIdentityKey(peerPrivateAddress) {
        const keySerialized = await this.retrieveIdentityKeySerialized(peerPrivateAddress);
        return keySerialized ? derDeserializeRSAPublicKey(keySerialized) : null;
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
            publicKeyDer: await derSerializePublicKey(key.publicKey),
            publicKeyId: key.keyId,
        };
        try {
            await this.saveSessionKeyData(keyData, peerPrivateAddress);
        }
        catch (error) {
            throw new KeyStoreError(error, 'Failed to save public session key');
        }
    }
    async retrieveLastSessionKey(peerPrivateAddress) {
        const keyData = await this.fetchSessionKeyDataOrWrapError(peerPrivateAddress);
        if (!keyData) {
            return null;
        }
        const publicKey = await derDeserializeECDHPublicKey(keyData.publicKeyDer);
        return { publicKey, keyId: keyData.publicKeyId };
    }
    async fetchSessionKeyDataOrWrapError(peerPrivateAddress) {
        try {
            return await this.retrieveSessionKeyData(peerPrivateAddress);
        }
        catch (error) {
            throw new KeyStoreError(error, 'Failed to retrieve key');
        }
    }
}
//# sourceMappingURL=PublicKeyStore.js.map