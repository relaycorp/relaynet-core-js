import uuid4 from 'uuid4';

import Certificate from '../pki/Certificate';

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
    payloadPlaintext?: ArrayBuffer,
    options: Partial<MessageOptions> = {},
  ) {
    this.id = options.id || uuid4();
    this.date = options.date || new Date();
    this.ttl = options.ttl !== undefined ? options.ttl : DEFAULT_TTL_SECONDS;

    //region Payload
    if (payloadPlaintext) {
      this.importPayload(payloadPlaintext);
    }
    //endregion

    //region Sender certificate (chain)
    const initialChain = options.senderCertificateChain || new Set([]);
    this.senderCertificateChain = new Set([...initialChain, senderCertificate]);
    //endregion
  }

  public abstract exportPayload(): ArrayBuffer;
  protected abstract importPayload(payloadPlaintext: ArrayBuffer): void;
}
