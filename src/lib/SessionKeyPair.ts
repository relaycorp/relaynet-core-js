import { generateRandom64BitValue } from './crypto_wrappers/_utils';
import { generateECDHKeyPair } from './crypto_wrappers/keys';
import { SessionKey } from './SessionKey';

export class SessionKeyPair {
  /**
   * Generate a new session key pair.
   */
  public static async generate(): Promise<SessionKeyPair> {
    const keyPair = await generateECDHKeyPair();
    const keyId = await generateRandom64BitValue();
    const sessionKey: SessionKey = { keyId: Buffer.from(keyId), publicKey: keyPair.publicKey };
    return new SessionKeyPair(sessionKey, keyPair.privateKey);
  }

  constructor(public readonly sessionKey: SessionKey, public readonly privateKey: CryptoKey) {}
}
