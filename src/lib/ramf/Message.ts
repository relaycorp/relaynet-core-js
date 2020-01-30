import uuid4 from 'uuid4';

import { SignatureOptions } from '../..';
import Certificate from '../crypto_wrappers/x509/Certificate';
import InvalidMessageError from './InvalidMessageError';

const DEFAULT_TTL_SECONDS = 5 * 60; // 5 minutes

interface MessageOptions {
  readonly id: string;
  readonly date: Date;
  readonly ttl: number;
  readonly senderCaCertificateChain: readonly Certificate[];
}

/**
 * Relaynet Abstract Message Format, version 1.
 */
export default abstract class Message {
  public readonly id: string;
  public readonly date: Date;
  public readonly ttl: number;
  public readonly senderCaCertificateChain: readonly Certificate[];

  constructor(
    readonly recipientAddress: string,
    readonly senderCertificate: Certificate,
    readonly payloadSerialized: Buffer,
    options: Partial<MessageOptions> = {},
  ) {
    this.id = options.id || uuid4();
    this.date = options.date || new Date();
    this.ttl = options.ttl !== undefined ? options.ttl : DEFAULT_TTL_SECONDS;

    this.senderCaCertificateChain = options.senderCaCertificateChain ?? [];
  }

  // This method would be concrete if TS allowed us to store the message type and version as
  // properties
  public abstract async serialize(
    senderPrivateKey: CryptoKey,
    signatureOptions?: SignatureOptions,
  ): Promise<ArrayBuffer>;

  public async validate(trustedCertificates?: readonly Certificate[]): Promise<void> {
    if (trustedCertificates) {
      await this.validationAuthorization(trustedCertificates);
    }
  }

  protected async validationAuthorization(
    trustedCertificates: readonly Certificate[],
  ): Promise<void> {
    // tslint:disable-next-line:no-let
    let certificationPath: readonly Certificate[];
    try {
      certificationPath = await this.senderCertificate.getCertificationPath(
        this.senderCaCertificateChain,
        trustedCertificates,
      );
    } catch (error) {
      throw new InvalidMessageError(error, 'Sender is not authorized');
    }

    const recipientCertificate = certificationPath[1];
    const recipientPrivateAddress = await recipientCertificate.calculateSubjectPrivateAddress();
    if (recipientPrivateAddress !== this.recipientAddress) {
      throw new InvalidMessageError(`Sender is not authorized to reach ${this.recipientAddress}`);
    }
  }
}
