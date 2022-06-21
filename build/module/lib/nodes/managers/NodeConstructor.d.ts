import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { Node } from '../Node';
export declare type NodeConstructor<N extends Node<any>> = new (privateAddress: string, identityPrivateKey: CryptoKey, keyStores: KeyStoreSet, cryptoOptions: Partial<NodeCryptoOptions>) => N;
