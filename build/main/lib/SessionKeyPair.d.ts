import { SessionKey } from './SessionKey';
export declare class SessionKeyPair {
    readonly sessionKey: SessionKey;
    readonly privateKey: CryptoKey;
    /**
     * Generate a new session key pair.
     */
    static generate(): Promise<SessionKeyPair>;
    constructor(sessionKey: SessionKey, privateKey: CryptoKey);
}
