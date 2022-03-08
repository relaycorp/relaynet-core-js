import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { SessionKey } from '../../SessionKey';
import { SessionKeyPair } from '../../SessionKeyPair';
import { Node } from '../Node';
import { NodeCryptoOptions } from '../NodeCryptoOptions';

export abstract class NodeManager<N extends Node<any>> {
  protected abstract readonly nodeClass: new (
    privateKey: CryptoKey,
    keyStores: KeyStoreSet,
    cryptoOptions: Partial<NodeCryptoOptions>,
  ) => N;

  constructor(
    protected keyStores: KeyStoreSet,
    protected cryptoOptions: Partial<NodeCryptoOptions> = {},
  ) {}

  public async getPrivate(nodePrivateAddress: string): Promise<N | null> {
    const nodePrivateKey = await this.keyStores.privateKeyStore.retrieveIdentityKey(
      nodePrivateAddress,
    );
    if (!nodePrivateKey) {
      return null;
    }
    return new this.nodeClass(nodePrivateKey, this.keyStores, this.cryptoOptions);
  }

  /**
   * Generate and store a new session key.
   *
   * @param peerPrivateAddress The peer to bind the key to, unless it's an initial key
   */
  public async generateSessionKey(peerPrivateAddress?: string): Promise<SessionKey> {
    const { sessionKey, privateKey } = await SessionKeyPair.generate();

    if (peerPrivateAddress) {
      await this.keyStores.privateKeyStore.saveBoundSessionKey(
        privateKey,
        sessionKey.keyId,
        peerPrivateAddress,
      );
    } else {
      await this.keyStores.privateKeyStore.saveUnboundSessionKey(privateKey, sessionKey.keyId);
    }

    return sessionKey;
  }
}
