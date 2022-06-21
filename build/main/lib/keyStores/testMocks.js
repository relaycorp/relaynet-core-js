"use strict";
// tslint:disable:max-classes-per-file no-object-mutation readonly-keyword readonly-array
Object.defineProperty(exports, "__esModule", { value: true });
exports.MockKeyStoreSet = exports.MockCertificateStore = exports.MockPublicKeyStore = exports.MockPrivateKeyStore = void 0;
const CertificateStore_1 = require("./CertificateStore");
const PrivateKeyStore_1 = require("./PrivateKeyStore");
const PublicKeyStore_1 = require("./PublicKeyStore");
class MockPrivateKeyStore extends PrivateKeyStore_1.PrivateKeyStore {
    constructor(failOnSave = false, failOnFetch = false) {
        super();
        this.failOnSave = failOnSave;
        this.failOnFetch = failOnFetch;
        this.identityKeys = {};
        this.sessionKeys = {};
    }
    clear() {
        this.identityKeys = {};
        this.sessionKeys = {};
    }
    async retrieveIdentityKey(privateAddress) {
        return this.identityKeys[privateAddress] ?? null;
    }
    async saveIdentityKey(privateAddress, privateKey) {
        if (this.failOnSave) {
            throw new Error('Denied');
        }
        this.identityKeys[privateAddress] = privateKey;
    }
    async saveSessionKeySerialized(keyId, keySerialized, privateAddress, peerPrivateAddress) {
        if (this.failOnSave) {
            throw new Error('Denied');
        }
        this.sessionKeys[keyId] = {
            keySerialized,
            peerPrivateAddress,
            privateAddress,
        };
    }
    async retrieveSessionKeyData(keyId) {
        if (this.failOnFetch) {
            throw new Error('Denied');
        }
        return this.sessionKeys[keyId] ?? null;
    }
}
exports.MockPrivateKeyStore = MockPrivateKeyStore;
class MockPublicKeyStore extends PublicKeyStore_1.PublicKeyStore {
    constructor(failOnSave = false, fetchError) {
        super();
        this.failOnSave = failOnSave;
        this.fetchError = fetchError;
        this.identityKeys = {};
        this.sessionKeys = {};
    }
    clear() {
        this.sessionKeys = {};
        this.identityKeys = {};
    }
    registerSessionKey(keyData, peerPrivateAddress) {
        this.sessionKeys[peerPrivateAddress] = keyData;
    }
    async retrieveIdentityKeySerialized(peerPrivateAddress) {
        return this.identityKeys[peerPrivateAddress] ?? null;
    }
    async retrieveSessionKeyData(peerPrivateAddress) {
        if (this.fetchError) {
            throw this.fetchError;
        }
        const keyData = this.sessionKeys[peerPrivateAddress];
        return keyData ?? null;
    }
    async saveIdentityKeySerialized(keySerialized, peerPrivateAddress) {
        this.identityKeys[peerPrivateAddress] = keySerialized;
    }
    async saveSessionKeyData(keyData, peerPrivateAddress) {
        if (this.failOnSave) {
            throw new Error('Denied');
        }
        this.sessionKeys[peerPrivateAddress] = keyData;
    }
}
exports.MockPublicKeyStore = MockPublicKeyStore;
class MockCertificateStore extends CertificateStore_1.CertificateStore {
    constructor() {
        super(...arguments);
        this.dataByPrivateAddress = {};
    }
    clear() {
        this.dataByPrivateAddress = {};
    }
    async forceSave(path, issuerPrivateAddress) {
        await this.saveData(path.serialize(), await path.leafCertificate.calculateSubjectPrivateAddress(), path.leafCertificate.expiryDate, issuerPrivateAddress);
    }
    async deleteExpired() {
        throw new Error('Not implemented');
    }
    async retrieveAllSerializations(subjectPrivateAddress, issuerPrivateAddress) {
        const certificateData = this.dataByPrivateAddress[subjectPrivateAddress] ?? [];
        const matchingCertificateData = certificateData.filter((d) => d.issuerPrivateAddress === issuerPrivateAddress);
        if (matchingCertificateData.length === 0) {
            return [];
        }
        return matchingCertificateData.map((d) => d.serialization);
    }
    async retrieveLatestSerialization(subjectPrivateAddress, issuerPrivateAddress) {
        const certificateData = this.dataByPrivateAddress[subjectPrivateAddress] ?? [];
        const matchingCertificateData = certificateData.filter((d) => d.issuerPrivateAddress === issuerPrivateAddress);
        if (matchingCertificateData.length === 0) {
            return null;
        }
        const dataSorted = matchingCertificateData.sort((a, b) => b.expiryDate.getTime() - a.expiryDate.getTime());
        return dataSorted[0].serialization;
    }
    async saveData(serialization, subjectPrivateAddress, subjectCertificateExpiryDate, issuerPrivateAddress) {
        const mockData = {
            serialization,
            expiryDate: subjectCertificateExpiryDate,
            issuerPrivateAddress,
        };
        const originalCertificateData = this.dataByPrivateAddress[subjectPrivateAddress] ?? [];
        this.dataByPrivateAddress[subjectPrivateAddress] = [...originalCertificateData, mockData];
    }
}
exports.MockCertificateStore = MockCertificateStore;
class MockKeyStoreSet {
    constructor() {
        this.certificateStore = new MockCertificateStore();
        this.privateKeyStore = new MockPrivateKeyStore();
        this.publicKeyStore = new MockPublicKeyStore();
    }
    clear() {
        this.certificateStore.clear();
        this.privateKeyStore.clear();
        this.publicKeyStore.clear();
    }
}
exports.MockKeyStoreSet = MockKeyStoreSet;
//# sourceMappingURL=testMocks.js.map