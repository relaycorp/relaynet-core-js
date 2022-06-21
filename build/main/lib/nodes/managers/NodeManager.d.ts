import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { Node } from '../Node';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { NodeConstructor } from './NodeConstructor';
export declare abstract class NodeManager<N extends Node<any>> {
    protected keyStores: KeyStoreSet;
    protected cryptoOptions: Partial<NodeCryptoOptions>;
    protected abstract readonly defaultNodeConstructor: NodeConstructor<N>;
    constructor(keyStores: KeyStoreSet, cryptoOptions?: Partial<NodeCryptoOptions>);
    /**
     * Get node by `privateAddress`.
     *
     * @param privateAddress
     */
    get(privateAddress: string): Promise<N | null>;
    /**
     * Get node by `privateAddress` but return instance of custom `customNodeClass`.
     *
     * @param privateAddress
     * @param customNodeClass
     */
    get<C extends N>(privateAddress: string, customNodeClass: NodeConstructor<C>): Promise<C | null>;
}
