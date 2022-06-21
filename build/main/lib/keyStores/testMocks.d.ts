/// <reference types="node" />
import { CertificationPath } from '../pki/CertificationPath';
import { CertificateStore } from './CertificateStore';
import { KeyStoreSet } from './KeyStoreSet';
import { PrivateKeyStore, SessionPrivateKeyData } from './PrivateKeyStore';
import { PublicKeyStore, SessionPublicKeyData } from './PublicKeyStore';
export declare class MockPrivateKeyStore extends PrivateKeyStore {
    protected readonly failOnSave: boolean;
    protected readonly failOnFetch: boolean;
    identityKeys: {
        [privateAddress: string]: CryptoKey;
    };
    sessionKeys: {
        [keyId: string]: SessionPrivateKeyData;
    };
    constructor(failOnSave?: boolean, failOnFetch?: boolean);
    clear(): void;
    retrieveIdentityKey(privateAddress: string): Promise<CryptoKey | null>;
    saveIdentityKey(privateAddress: string, privateKey: CryptoKey): Promise<void>;
    protected saveSessionKeySerialized(keyId: string, keySerialized: Buffer, privateAddress: string, peerPrivateAddress?: string): Promise<void>;
    protected retrieveSessionKeyData(keyId: string): Promise<SessionPrivateKeyData | null>;
}
export declare class MockPublicKeyStore extends PublicKeyStore {
    protected readonly failOnSave: boolean;
    protected fetchError?: Error | undefined;
    identityKeys: {
        [peerPrivateAddress: string]: Buffer;
    };
    sessionKeys: {
        [key: string]: SessionPublicKeyData;
    };
    constructor(failOnSave?: boolean, fetchError?: Error | undefined);
    clear(): void;
    registerSessionKey(keyData: SessionPublicKeyData, peerPrivateAddress: string): void;
    protected retrieveIdentityKeySerialized(peerPrivateAddress: string): Promise<Buffer | null>;
    protected retrieveSessionKeyData(peerPrivateAddress: string): Promise<SessionPublicKeyData | null>;
    protected saveIdentityKeySerialized(keySerialized: Buffer, peerPrivateAddress: string): Promise<void>;
    protected saveSessionKeyData(keyData: SessionPublicKeyData, peerPrivateAddress: string): Promise<void>;
}
interface MockStoredCertificateData {
    readonly expiryDate: Date;
    readonly serialization: ArrayBuffer;
    readonly issuerPrivateAddress: string;
}
export declare class MockCertificateStore extends CertificateStore {
    dataByPrivateAddress: {
        [privateAddress: string]: MockStoredCertificateData[];
    };
    clear(): void;
    forceSave(path: CertificationPath, issuerPrivateAddress: string): Promise<void>;
    deleteExpired(): Promise<void>;
    protected retrieveAllSerializations(subjectPrivateAddress: string, issuerPrivateAddress: string): Promise<readonly ArrayBuffer[]>;
    protected retrieveLatestSerialization(subjectPrivateAddress: string, issuerPrivateAddress: string): Promise<ArrayBuffer | null>;
    protected saveData(serialization: ArrayBuffer, subjectPrivateAddress: string, subjectCertificateExpiryDate: Date, issuerPrivateAddress: string): Promise<void>;
}
export declare class MockKeyStoreSet implements KeyStoreSet {
    readonly certificateStore: MockCertificateStore;
    readonly privateKeyStore: MockPrivateKeyStore;
    readonly publicKeyStore: MockPublicKeyStore;
    clear(): void;
}
export {};
