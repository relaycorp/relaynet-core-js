/// <reference types="node" />
import { SessionKey } from '../SessionKey';
export interface SessionPublicKeyData {
    readonly publicKeyId: Buffer;
    readonly publicKeyDer: Buffer;
    readonly publicKeyCreationTime: Date;
}
export declare abstract class PublicKeyStore {
    saveIdentityKey(key: CryptoKey): Promise<void>;
    retrieveIdentityKey(peerPrivateAddress: string): Promise<CryptoKey | null>;
    saveSessionKey(key: SessionKey, peerPrivateAddress: string, creationTime: Date): Promise<void>;
    retrieveLastSessionKey(peerPrivateAddress: string): Promise<SessionKey | null>;
    protected abstract retrieveIdentityKeySerialized(peerPrivateAddress: string): Promise<Buffer | null>;
    protected abstract retrieveSessionKeyData(peerPrivateAddress: string): Promise<SessionPublicKeyData | null>;
    protected abstract saveIdentityKeySerialized(keySerialized: Buffer, peerPrivateAddress: string): Promise<void>;
    protected abstract saveSessionKeyData(keyData: SessionPublicKeyData, peerPrivateAddress: string): Promise<void>;
    private fetchSessionKeyDataOrWrapError;
}
