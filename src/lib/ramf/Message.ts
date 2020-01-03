import uuid4 from 'uuid4';

import Certificate from '../crypto_wrappers/x509/Certificate';
import Payload from './Payload';

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
export default abstract class Message<PayloadSpecialization extends Payload> {
  public readonly id: string;
  public readonly date: Date;
  public readonly ttl: number;
  public readonly senderCertificateChain: ReadonlySet<Certificate>;

  constructor(
    readonly recipientAddress: string,
    readonly senderCertificate: Certificate,
    readonly payloadSerialized: ArrayBuffer,
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

  public abstract unwrapPayload(privateKey: CryptoKey): PayloadSpecialization;
}
