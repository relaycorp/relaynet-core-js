import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { Node } from '../Node';

export type NodeConstructor<N extends Node<any>> = new (
  privateAddress: string,
  identityPrivateKey: CryptoKey,
  keyStores: KeyStoreSet,
  cryptoOptions: Partial<NodeCryptoOptions>,
) => N;
