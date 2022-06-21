"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const keys_1 = require("../crypto_wrappers/keys");
const KeyStoreError_1 = require("./KeyStoreError");
const testMocks_1 = require("./testMocks");
const STORE = new testMocks_1.MockPublicKeyStore();
beforeEach(() => {
    STORE.clear();
});
describe('Identity keys', () => {
    let publicKey;
    let peerPrivateAddress;
    beforeAll(async () => {
        const keyPair = await (0, keys_1.generateRSAKeyPair)();
        publicKey = keyPair.publicKey;
        peerPrivateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(publicKey);
    });
    describe('saveIdentityKey', () => {
        test('Key should be stored', async () => {
            await STORE.saveIdentityKey(publicKey);
            expect(STORE.identityKeys).toHaveProperty(peerPrivateAddress, await (0, keys_1.derSerializePublicKey)(publicKey));
        });
    });
    describe('retrieveIdentityKey', () => {
        test('Key should be returned if it exists', async () => {
            await STORE.saveIdentityKey(publicKey);
            const publicKeyRetrieved = await STORE.retrieveIdentityKey(peerPrivateAddress);
            await expect((0, keys_1.derSerializePublicKey)(publicKeyRetrieved)).resolves.toEqual(await (0, keys_1.derSerializePublicKey)(publicKey));
        });
        test('Null should be returned if it does not exist', async () => {
            await expect(STORE.retrieveIdentityKey(peerPrivateAddress)).resolves.toBeNull();
        });
    });
});
describe('Session keys', () => {
    const CREATION_DATE = new Date();
    const sessionKeyId = Buffer.from([1, 3, 5, 7, 9]);
    let sessionPublicKey;
    const peerPrivateAddress = '0deadbeef';
    beforeAll(async () => {
        const keyPair = await (0, keys_1.generateECDHKeyPair)();
        sessionPublicKey = keyPair.publicKey;
    });
    describe('retrieveLastSessionKey', () => {
        test('Key data should be returned if key for recipient exists', async () => {
            const keyData = {
                publicKeyCreationTime: CREATION_DATE,
                publicKeyDer: await (0, keys_1.derSerializePublicKey)(sessionPublicKey),
                publicKeyId: sessionKeyId,
            };
            STORE.registerSessionKey(keyData, peerPrivateAddress);
            const key = await STORE.retrieveLastSessionKey(peerPrivateAddress);
            expect(key?.keyId).toEqual(sessionKeyId);
            expect(await (0, keys_1.derSerializePublicKey)(key.publicKey)).toEqual(keyData.publicKeyDer);
        });
        test('Null should be returned if key for recipient does not exist', async () => {
            await expect(STORE.retrieveLastSessionKey(peerPrivateAddress)).resolves.toBeNull();
        });
        test('Retrieval errors should be wrapped', async () => {
            const fetchError = new Error('Ho noes');
            const bogusStore = new testMocks_1.MockPublicKeyStore(false, fetchError);
            await expect(bogusStore.retrieveLastSessionKey(peerPrivateAddress)).rejects.toEqual(new KeyStoreError_1.KeyStoreError(fetchError, 'Failed to retrieve key'));
        });
    });
    describe('saveSessionKey', () => {
        test('Key data should be saved if there is no prior key for recipient', async () => {
            await STORE.saveSessionKey({ keyId: sessionKeyId, publicKey: sessionPublicKey }, peerPrivateAddress, CREATION_DATE);
            const keyData = STORE.sessionKeys[peerPrivateAddress];
            const expectedKeyData = {
                publicKeyCreationTime: CREATION_DATE,
                publicKeyDer: await (0, keys_1.derSerializePublicKey)(sessionPublicKey),
                publicKeyId: sessionKeyId,
            };
            expect(keyData).toEqual(expectedKeyData);
        });
        test('Key data should be saved if prior key is older', async () => {
            const oldKeyData = {
                publicKeyCreationTime: CREATION_DATE,
                publicKeyDer: await (0, keys_1.derSerializePublicKey)(sessionPublicKey),
                publicKeyId: sessionKeyId,
            };
            STORE.registerSessionKey(oldKeyData, peerPrivateAddress);
            const newPublicKeyId = Buffer.concat([sessionKeyId, Buffer.from([1, 0])]);
            const newPublicKey = (await (0, keys_1.generateECDHKeyPair)()).publicKey;
            const newPublicKeyDate = new Date(CREATION_DATE);
            newPublicKeyDate.setHours(newPublicKeyDate.getHours() + 1);
            await STORE.saveSessionKey({ publicKey: newPublicKey, keyId: newPublicKeyId }, peerPrivateAddress, newPublicKeyDate);
            const keyData = STORE.sessionKeys[peerPrivateAddress];
            const expectedKeyData = {
                publicKeyCreationTime: newPublicKeyDate,
                publicKeyDer: await (0, keys_1.derSerializePublicKey)(newPublicKey),
                publicKeyId: newPublicKeyId,
            };
            expect(keyData).toEqual(expectedKeyData);
        });
        test('Key data should not be saved if prior key is newer', async () => {
            const currentKeyData = {
                publicKeyCreationTime: CREATION_DATE,
                publicKeyDer: await (0, keys_1.derSerializePublicKey)(sessionPublicKey),
                publicKeyId: sessionKeyId,
            };
            STORE.registerSessionKey(currentKeyData, peerPrivateAddress);
            const olderPublicKeyId = Buffer.concat([sessionKeyId, sessionKeyId]);
            const olderPublicKey = (await (0, keys_1.generateECDHKeyPair)()).publicKey;
            const olderPublicKeyDate = new Date(CREATION_DATE);
            olderPublicKeyDate.setHours(olderPublicKeyDate.getHours() - 1);
            await STORE.saveSessionKey({ publicKey: olderPublicKey, keyId: olderPublicKeyId }, peerPrivateAddress, olderPublicKeyDate);
            const keyData = STORE.sessionKeys[peerPrivateAddress];
            expect(keyData).toEqual(currentKeyData);
        });
        test('Any error should be propagated', async () => {
            const bogusStore = new testMocks_1.MockPublicKeyStore(true);
            await expect(bogusStore.saveSessionKey({ keyId: sessionKeyId, publicKey: sessionPublicKey }, peerPrivateAddress, CREATION_DATE)).rejects.toEqual(new KeyStoreError_1.KeyStoreError('Failed to save public session key: Denied'));
        });
    });
});
//# sourceMappingURL=PublicKeyStore.spec.js.map