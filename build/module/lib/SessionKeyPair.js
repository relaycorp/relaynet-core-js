import { generateRandom64BitValue } from './crypto_wrappers/_utils';
import { generateECDHKeyPair } from './crypto_wrappers/keys';
export class SessionKeyPair {
    sessionKey;
    privateKey;
    /**
     * Generate a new session key pair.
     */
    static async generate() {
        const keyPair = await generateECDHKeyPair();
        const keyId = await generateRandom64BitValue();
        const sessionKey = { keyId: Buffer.from(keyId), publicKey: keyPair.publicKey };
        return new SessionKeyPair(sessionKey, keyPair.privateKey);
    }
    constructor(sessionKey, privateKey) {
        this.sessionKey = sessionKey;
        this.privateKey = privateKey;
    }
}
//# sourceMappingURL=SessionKeyPair.js.map