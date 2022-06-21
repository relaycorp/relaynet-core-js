/* tslint:disable:max-classes-per-file */
import { derDeserializeECDHPrivateKey, derSerializePrivateKey, generateRSAKeyPair, getPrivateAddressFromIdentityKey, } from '../crypto_wrappers/keys';
import { KeyStoreError } from './KeyStoreError';
import UnknownKeyError from './UnknownKeyError';
export class PrivateKeyStore {
    //region Identity keys
    async generateIdentityKeyPair(keyOptions = {}) {
        const keyPair = await this.generateRSAKeyPair(keyOptions);
        const privateAddress = await getPrivateAddressFromIdentityKey(keyPair.publicKey);
        try {
            await this.saveIdentityKey(privateAddress, keyPair.privateKey);
        }
        catch (err) {
            throw new KeyStoreError(err, `Failed to save key for ${privateAddress}`);
        }
        return { ...keyPair, privateAddress };
    }
    //endregion
    //region Session keys
    async saveSessionKey(privateKey, keyId, privateAddress, peerPrivateAddress) {
        const keyIdString = keyId.toString('hex');
        const privateKeyDer = await derSerializePrivateKey(privateKey);
        try {
            await this.saveSessionKeySerialized(keyIdString, privateKeyDer, privateAddress, peerPrivateAddress);
        }
        catch (error) {
            throw new KeyStoreError(error, `Failed to save key ${keyIdString}`);
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
            throw new UnknownKeyError(`Key ${keyId.toString('hex')} is bound`);
        }
        return derDeserializeECDHPrivateKey(keyData.keySerialized, 'P-256');
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
            throw new UnknownKeyError(`Session key ${keyIdHex} is bound to another recipient ` +
                `(${keyData.peerPrivateAddress}, not ${peerPrivateAddress})`);
        }
        return derDeserializeECDHPrivateKey(keyData.keySerialized, 'P-256');
    }
    async retrieveSessionKeyDataOrThrowError(keyId, privateAddress) {
        const keyIdHex = keyId.toString('hex');
        let keyData;
        try {
            keyData = await this.retrieveSessionKeyData(keyIdHex);
        }
        catch (error) {
            throw new KeyStoreError(error, `Failed to retrieve key`);
        }
        if (keyData === null) {
            throw new UnknownKeyError(`Key ${keyIdHex} does not exist`);
        }
        if (keyData.privateAddress !== privateAddress) {
            throw new UnknownKeyError('Key is owned by a different node');
        }
        return keyData;
    }
    async generateRSAKeyPair(keyOptions) {
        return generateRSAKeyPair(keyOptions);
    }
}
//# sourceMappingURL=PrivateKeyStore.js.map