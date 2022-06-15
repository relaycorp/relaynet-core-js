import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { Node } from '../Node';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { NodeConstructor } from './NodeConstructor';

export abstract class NodeManager<N extends Node<any>> {
  protected abstract readonly defaultNodeConstructor: NodeConstructor<N>;

  constructor(
    protected keyStores: KeyStoreSet,
    protected cryptoOptions: Partial<NodeCryptoOptions> = {},
  ) {}

  /**
   * Get node by `privateAddress`.
   *
   * @param privateAddress
   */
  public async get(privateAddress: string): Promise<N | null>;
  /**
   * Get node by `privateAddress` but return instance of custom `customNodeClass`.
   *
   * @param privateAddress
   * @param customNodeClass
   */
  public async get<C extends N>(
    privateAddress: string,
    customNodeClass: NodeConstructor<C>,
  ): Promise<C | null>;
  public async get(
    privateAddress: string,
    nodeConstructor?: NodeConstructor<N>,
  ): Promise<N | null> {
    const nodePrivateKey = await this.keyStores.privateKeyStore.retrieveIdentityKey(privateAddress);
    if (!nodePrivateKey) {
      return null;
    }
    const constructor = nodeConstructor ?? this.defaultNodeConstructor;
    return new constructor(privateAddress, nodePrivateKey, this.keyStores, this.cryptoOptions);
  }
}
