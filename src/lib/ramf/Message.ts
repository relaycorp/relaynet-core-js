import uuid4 from 'uuid4';

import Certificate from '../pki/Certificate';
import * as field_validators from './_field_validators';

const DEFAULT_TTL = 5 * 60; // 5 minutes

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
    options: Partial<MessageOptions> = {}
  ) {
    //region Recipient address
    field_validators.validateRecipientAddressLength(recipientAddress);
    //endregion

    //region Message id
    if (options.id) {
      field_validators.validateMessageIdLength(options.id);
    }
    this.id = options.id || uuid4();
    //endregion

    //region Date
    const customTimestampMs = options.date && options.date.getTime();
    if (customTimestampMs) {
      field_validators.validateDate(customTimestampMs);
    }
    this.date = customTimestampMs ? new Date(customTimestampMs) : new Date();
    //endregion

    //region TTL
    if (options.ttl) {
      field_validators.validateTtl(options.ttl);
    }
    this.ttl = Object.keys(options).includes('ttl') ? (options.ttl as number) : DEFAULT_TTL;
    //endregion

    //region Payload
    if (payloadPlaintext) {
      this.importPayload(payloadPlaintext);
    }
    //endregion

    //region Sender certificate (chain)
    this.senderCertificateChain = options.senderCertificateChain || new Set();
    //endregion
  }

  public abstract exportPayload(): ArrayBuffer;
  protected abstract importPayload(payloadPlaintext: ArrayBuffer): void;
}
