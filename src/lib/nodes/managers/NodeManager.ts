import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { NodeCryptoOptions } from '../NodeCryptoOptions';

export abstract class NodeManager {
  constructor(
    protected keyStores: KeyStoreSet,
    protected cryptoOptions: Partial<NodeCryptoOptions> = {},
  ) {}
}
