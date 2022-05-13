import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { SessionKey } from '../../SessionKey';
import { SessionKeyPair } from '../../SessionKeyPair';
import { NodeCryptoOptions } from '../NodeCryptoOptions';

export abstract class NodeManager {
  constructor(
    protected keyStores: KeyStoreSet,
    protected cryptoOptions: Partial<NodeCryptoOptions> = {},
  ) {}

  /**
   * Generate and store a new session key.
   *
   * @param peerPrivateAddress The peer to bind the key to, unless it's an initial key
   */
  public async generateSessionKey(peerPrivateAddress?: string): Promise<SessionKey> {
    const { sessionKey, privateKey } = await SessionKeyPair.generate();

    if (peerPrivateAddress) {
      await this.keyStores.privateKeyStore.saveSessionKey(
        privateKey,
        sessionKey.keyId,
        peerPrivateAddress,
      );
    } else {
      await this.keyStores.privateKeyStore.saveSessionKey(privateKey, sessionKey.keyId);
    }

    return sessionKey;
  }
}
