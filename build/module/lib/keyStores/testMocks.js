// tslint:disable:max-classes-per-file no-object-mutation readonly-keyword readonly-array
import { CertificateStore } from './CertificateStore';
import { PrivateKeyStore } from './PrivateKeyStore';
import { PublicKeyStore } from './PublicKeyStore';
export class MockPrivateKeyStore extends PrivateKeyStore {
    failOnSave;
    failOnFetch;
    identityKeys = {};
    sessionKeys = {};
    constructor(failOnSave = false, failOnFetch = false) {
        super();
        this.failOnSave = failOnSave;
        this.failOnFetch = failOnFetch;
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
export class MockPublicKeyStore extends PublicKeyStore {
    failOnSave;
    fetchError;
    identityKeys = {};
    sessionKeys = {};
    constructor(failOnSave = false, fetchError) {
        super();
        this.failOnSave = failOnSave;
        this.fetchError = fetchError;
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
export class MockCertificateStore extends CertificateStore {
    dataByPrivateAddress = {};
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
export class MockKeyStoreSet {
    certificateStore = new MockCertificateStore();
    privateKeyStore = new MockPrivateKeyStore();
    publicKeyStore = new MockPublicKeyStore();
    clear() {
        this.certificateStore.clear();
        this.privateKeyStore.clear();
        this.publicKeyStore.clear();
    }
}
//# sourceMappingURL=testMocks.js.map