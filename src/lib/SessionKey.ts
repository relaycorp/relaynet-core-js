import { generateRandom64BitValue } from './crypto_wrappers/_utils';
import { generateECDHKeyPair } from './crypto_wrappers/keys';

/** Key of the sender or recipient of the EnvelopedData value using the Channel Session Protocol */
export class SessionKey {
  /**
   * Generate a new session key.
   */
  public static async generate(): Promise<{
    readonly sessionKey: SessionKey;
    readonly privateKey: CryptoKey;
  }> {
    const keyPair = await generateECDHKeyPair();
    const keyId = await generateRandom64BitValue();
    const sessionKey = new SessionKey(Buffer.from(keyId), keyPair.publicKey);
    return { sessionKey, privateKey: keyPair.privateKey };
  }

  /**
   * @param keyId Id of the ECDH key pair
   * @param publicKey Public key of the (EC)DH key pair
   */
  constructor(public readonly keyId: Buffer, public readonly publicKey: CryptoKey) {}
}
