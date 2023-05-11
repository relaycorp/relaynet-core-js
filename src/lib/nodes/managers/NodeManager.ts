import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { NodeConstructor } from './NodeConstructor';
import { getRSAPublicKeyFromPrivate } from '../../crypto/keys/generation';
import { PayloadPlaintext } from '../../messages/payloads/PayloadPlaintext';
import { PeerInternetAddress } from '../peer';
import { Node } from '../Node';

export abstract class NodeManager<
  Payload extends PayloadPlaintext,
  PeerAddress extends PeerInternetAddress,
> {
  protected abstract readonly defaultNodeConstructor: NodeConstructor<Payload, PeerAddress>;

  constructor(
    public keyStores: KeyStoreSet,
    protected cryptoOptions: Partial<NodeCryptoOptions> = {},
  ) {}

  /**
   * Get node by `id`.
   *
   * @param id
   */
  public async get(id: string): Promise<Node<Payload, PeerAddress> | null>;
  /**
   * Get node by `id` but return instance of custom `customNodeClass`.
   *
   * @param id
   * @param customNodeClass
   */
  public async get<N extends Node<Payload, PeerAddress>>(
    id: string,
    customNodeClass: NodeConstructor<Payload, PeerAddress>,
  ): Promise<N | null>;
  public async get(
    id: string,
    nodeConstructor?: NodeConstructor<Payload, PeerAddress>,
  ): Promise<Node<Payload, PeerAddress> | null> {
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
