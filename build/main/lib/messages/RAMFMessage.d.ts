/// <reference types="node" />
import { EnvelopedData } from '../crypto_wrappers/cms/envelopedData';
import { SignatureOptions } from '../crypto_wrappers/cms/SignatureOptions';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { PrivateKeyStore } from '../keyStores/PrivateKeyStore';
import { SessionKey } from '../SessionKey';
import PayloadPlaintext from './payloads/PayloadPlaintext';
import { RecipientAddressType } from './RecipientAddressType';
interface MessageOptions {
    readonly id: string;
    readonly creationDate: Date;
    readonly ttl: number;
    readonly senderCaCertificateChain: readonly Certificate[];
}
interface PayloadUnwrapping<Payload extends PayloadPlaintext> {
    readonly payload: Payload;
    readonly senderSessionKey: SessionKey;
}
/**
 * Relaynet Abstract Message Format, version 1.
 */
export default abstract class RAMFMessage<Payload extends PayloadPlaintext> {
    readonly recipientAddress: string;
    readonly senderCertificate: Certificate;
    readonly payloadSerialized: Buffer;
    readonly id: string;
    readonly creationDate: Date;
    readonly ttl: number;
    readonly senderCaCertificateChain: readonly Certificate[];
    constructor(recipientAddress: string, senderCertificate: Certificate, payloadSerialized: Buffer, options?: Partial<MessageOptions>);
    get expiryDate(): Date;
    get isRecipientAddressPrivate(): boolean;
    /**
     * Return RAMF serialization of message.
     *
     * @param senderPrivateKey
     * @param signatureOptions
     */
    abstract serialize(senderPrivateKey: CryptoKey, signatureOptions?: Partial<SignatureOptions>): Promise<ArrayBuffer>;
    /**
     * Return certification path between sender's certificate and one certificate in
     * `trustedCertificates`.
     *
     * @param trustedCertificates
     */
    getSenderCertificationPath(trustedCertificates: readonly Certificate[]): Promise<readonly Certificate[]>;
    unwrapPayload(privateKey: CryptoKey): Promise<PayloadUnwrapping<Payload>>;
    unwrapPayload(privateKeyStore: PrivateKeyStore, privateAddress?: string): Promise<PayloadUnwrapping<Payload>>;
    /**
     * Report whether the message is valid.
     *
     * @param recipientAddressType The expected type of recipient address, if one is required
     * @param trustedCertificates If present, will check that the sender is authorized to send
     *   the message based on the trusted certificates.
     * @return The certification path from the sender to one of the `trustedCertificates` (if present)
     */
    validate(recipientAddressType?: RecipientAddressType, trustedCertificates?: readonly Certificate[]): Promise<readonly Certificate[] | null>;
    protected decryptPayload(payloadEnvelopedData: EnvelopedData, privateKeyOrStore: CryptoKey | PrivateKeyStore, privateAddress?: string): Promise<ArrayBuffer>;
    protected fetchPrivateKey(payloadEnvelopedData: EnvelopedData, privateKeyOrStore: CryptoKey | PrivateKeyStore, privateAddress?: string): Promise<CryptoKey>;
    protected abstract deserializePayload(payloadPlaintext: ArrayBuffer): Payload;
    private validateRecipientAddress;
    private validateAuthorization;
    private validateTiming;
}
export {};
