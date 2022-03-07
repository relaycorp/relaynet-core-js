import Certificate from '../../crypto_wrappers/x509/Certificate';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { Node } from '../Node';

export abstract class Channel<N extends Node<any>> {
  // noinspection TypeScriptAbstractClassConstructorCanBeMadeProtected
  /**
   * @internal
   */
  constructor(
    protected readonly node: N,
    protected readonly nodePrivateKey: CryptoKey,
    protected readonly nodeDeliveryAuth: Certificate,
    protected readonly peerPublicKey: CryptoKey,
    protected readonly keyStores: KeyStoreSet,
  ) {}
}
