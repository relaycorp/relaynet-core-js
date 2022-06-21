import Certificate from '../../crypto_wrappers/x509/Certificate';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import PayloadPlaintext from '../../messages/payloads/PayloadPlaintext';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
export declare abstract class Channel {
    protected readonly nodePrivateKey: CryptoKey;
    readonly nodeDeliveryAuth: Certificate;
    readonly peerPrivateAddress: string;
    readonly peerPublicKey: CryptoKey;
    protected readonly keyStores: KeyStoreSet;
    cryptoOptions: Partial<NodeCryptoOptions>;
    constructor(nodePrivateKey: CryptoKey, nodeDeliveryAuth: Certificate, peerPrivateAddress: string, peerPublicKey: CryptoKey, keyStores: KeyStoreSet, cryptoOptions?: Partial<NodeCryptoOptions>);
    /**
     * Encrypt and serialize the `payload`.
     *
     * @param payload
     *
     * Also store the new ephemeral session key.
     */
    wrapMessagePayload(payload: PayloadPlaintext | ArrayBuffer): Promise<ArrayBuffer>;
    abstract getOutboundRAMFAddress(): string;
    protected getNodePrivateAddress(): Promise<string>;
}
