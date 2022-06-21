import { KeyStoreSet } from '../keyStores/KeyStoreSet';
import { StubPayload } from '../ramf/_test_utils';
import { Node } from './Node';
import { NodeCryptoOptions } from './NodeCryptoOptions';
export declare class StubNode extends Node<StubPayload> {
    getPrivateKey(): CryptoKey;
    getKeyStores(): KeyStoreSet;
    getCryptoOptions(): Partial<NodeCryptoOptions>;
}
