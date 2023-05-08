import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { Node } from '../Node';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { NodeConstructor } from './NodeConstructor';
import { getRSAPublicKeyFromPrivate } from '../../crypto/keys/generation';

export abstract class NodeManager<N extends Node<any>> {
  protected abstract readonly defaultNodeConstructor: NodeConstructor<N>;

  constructor(
    public keyStores: KeyStoreSet,
    protected cryptoOptions: Partial<NodeCryptoOptions> = {},
  ) {}

  /**
   * Get node by `id`.
   *
   * @param id
   */
  public async get(id: string): Promise<N | null>;
  /**
   * Get node by `id` but return instance of custom `customNodeClass`.
   *
   * @param id
   * @param customNodeClass
   */
  public async get<C extends N>(id: string, customNodeClass: NodeConstructor<C>): Promise<C | null>;
  public async get(id: string, nodeConstructor?: NodeConstructor<N>): Promise<N | null> {
    const nodePrivateKey = await this.keyStores.privateKeyStore.retrieveIdentityKey(id);
    if (!nodePrivateKey) {
      return null;
    }
    const nodeKeyPair: CryptoKeyPair = {
      privateKey: nodePrivateKey,
      publicKey: await getRSAPublicKeyFromPrivate(nodePrivateKey),
    };
    const constructor = nodeConstructor ?? this.defaultNodeConstructor;
    return new constructor(id, nodeKeyPair, this.keyStores, this.cryptoOptions);
  }
}
