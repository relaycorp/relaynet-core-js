import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { Node } from '../Node';

export type NodeConstructor<N extends Node<any>> = new (
  id: string,
  identityKeyPair: CryptoKeyPair,
  keyStores: KeyStoreSet,
  cryptoOptions: Partial<NodeCryptoOptions>,
) => N;
