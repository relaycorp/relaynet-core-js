import { SignatureOptions } from '../..';
import RAMFMessage from '../messages/RAMFMessage';
/**
 * Maximum length of any RAMF message per RS-001.
 *
 * https://specs.relaynet.network/RS-001
 */
export declare const MAX_RAMF_MESSAGE_LENGTH = 9437184;
export declare const RAMF_MAX_TTL = 15552000;
/**
 * Maximum length of any SDU to be encapsulated in a CMS EnvelopedData value, per the RAMF spec.
 */
export declare const MAX_SDU_PLAINTEXT_LENGTH = 8322048;
/**
 * Sign and encode the current message.
 *
 * @param message The message to serialize.
 * @param concreteMessageTypeOctet
 * @param concreteMessageVersionOctet
 * @param senderPrivateKey The private key to sign the message.
 * @param signatureOptions Any signature options.
 */
export declare function serialize(message: RAMFMessage<any>, concreteMessageTypeOctet: number, concreteMessageVersionOctet: number, senderPrivateKey: CryptoKey, signatureOptions?: Partial<SignatureOptions>): Promise<ArrayBuffer>;
export declare function deserialize<M extends RAMFMessage<any>>(serialization: ArrayBuffer, concreteMessageTypeOctet: number, concreteMessageVersionOctet: number, messageClass: new (...args: readonly any[]) => M): Promise<M>;
