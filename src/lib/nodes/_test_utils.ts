import { KeyStoreSet } from '../keyStores/KeyStoreSet';
import { StubPayload } from '../ramf/_test_utils';
import { Node } from './Node';
import { NodeCryptoOptions } from './NodeCryptoOptions';

export class StubNode extends Node<StubPayload> {
  public getPrivateKey(): CryptoKey {
    return this.privateKey;
  }

  public getKeyStores(): KeyStoreSet {
    return this.keyStores;
  }

  public getCryptoOptions(): Partial<NodeCryptoOptions> {
    return this.cryptoOptions;
  }
}
