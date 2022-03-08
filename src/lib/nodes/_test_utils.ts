import { KeyStoreSet } from '../keyStores/KeyStoreSet';
import { StubPayload } from '../ramf/_test_utils';
import { Node } from './Node';

export class StubNode extends Node<StubPayload> {
  public getPrivateKey(): CryptoKey {
    return this.privateKey;
  }

  public getKeyStores(): KeyStoreSet {
    return this.keyStores;
  }
}
