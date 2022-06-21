import Certificate from '../crypto_wrappers/x509/Certificate';
import { KeyStoreSet } from '../keyStores/KeyStoreSet';
import PayloadPlaintext from '../messages/payloads/PayloadPlaintext';
import RAMFMessage from '../messages/RAMFMessage';
import { SessionKey } from '../SessionKey';
import { NodeCryptoOptions } from './NodeCryptoOptions';
import { Signer } from './signatures/Signer';
export declare abstract class Node<Payload extends PayloadPlaintext> {
    readonly privateAddress: string;
    protected readonly identityPrivateKey: CryptoKey;
    protected readonly keyStores: KeyStoreSet;
    protected readonly cryptoOptions: Partial<NodeCryptoOptions>;
    constructor(privateAddress: string, identityPrivateKey: CryptoKey, keyStores: KeyStoreSet, cryptoOptions: Partial<NodeCryptoOptions>);
    getIdentityPublicKey(): Promise<CryptoKey>;
    /**
     * Generate and store a new session key.
     *
     * @param peerPrivateAddress The peer to bind the key to, unless it's an initial key
     */
    generateSessionKey(peerPrivateAddress?: string): Promise<SessionKey>;
    getGSCSigner<S extends Signer>(peerPrivateAddress: string, signerClass: new (certificate: Certificate, privateKey: CryptoKey) => S): Promise<S | null>;
    /**
     * Decrypt and return the payload in the `message`.
     *
     * Also store the session key from the sender.
     *
     * @param message
     */
    unwrapMessagePayload<P extends Payload>(message: RAMFMessage<P>): Promise<P>;
}
