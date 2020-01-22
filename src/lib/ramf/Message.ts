import uuid4 from 'uuid4';

import { SignatureOptions } from '../..';
import Certificate from '../crypto_wrappers/x509/Certificate';

const DEFAULT_TTL_SECONDS = 5 * 60; // 5 minutes

interface MessageOptions {
  readonly id: string;
  readonly date: Date;
  readonly ttl: number;
  readonly senderCertificateChain: ReadonlySet<Certificate>;
}

/**
 * Relaynet Abstract Message Format, version 1.
 */
export default abstract class Message {
  public readonly id: string;
  public readonly date: Date;
  public readonly ttl: number;
  public readonly senderCertificateChain: ReadonlySet<Certificate>;

  constructor(
    readonly recipientAddress: string,
    readonly senderCertificate: Certificate,
    readonly payloadSerialized: Buffer,
    options: Partial<MessageOptions> = {},
  ) {
    this.id = options.id || uuid4();
    this.date = options.date || new Date();
    this.ttl = options.ttl !== undefined ? options.ttl : DEFAULT_TTL_SECONDS;

    //region Sender certificate (chain)
    const initialChain = options.senderCertificateChain || new Set([]);
    this.senderCertificateChain = new Set([...initialChain, senderCertificate]);
    //endregion
  }

  // This method would be concrete if TS allowed us to store the message type and version as
  // properties
  public abstract async serialize(
    senderPrivateKey: CryptoKey,
    signatureOptions?: SignatureOptions,
  ): Promise<ArrayBuffer>;
}
