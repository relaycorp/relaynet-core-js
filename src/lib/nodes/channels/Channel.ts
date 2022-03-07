import Certificate from '../../crypto_wrappers/x509/Certificate';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { Node } from '../Node';

export abstract class Channel<N extends Node<any>> {
  // noinspection TypeScriptAbstractClassConstructorCanBeMadeProtected
  /**
   * @internal
   */
  constructor(
    public readonly node: N,
    protected readonly nodePrivateKey: CryptoKey,
    public readonly nodeDeliveryAuth: Certificate,
    public readonly peerPrivateAddress: string,
    public readonly peerPublicKey: CryptoKey,
    protected readonly keyStores: KeyStoreSet,
  ) {}
}
