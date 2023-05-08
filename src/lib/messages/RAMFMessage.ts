import bufferToArray from 'buffer-to-arraybuffer';
import { setMilliseconds } from 'date-fns';
import uuid4 from 'uuid4';

import { EnvelopedData, SessionEnvelopedData } from '../crypto/cms/envelopedData';
import { SignatureOptions } from '../crypto/cms/SignatureOptions';
import { Certificate } from '../crypto/x509/Certificate';
import { PrivateKeyStore } from '../keyStores/PrivateKeyStore';
import { RAMFError } from '../ramf/RAMFError';
import { SessionKey } from '../SessionKey';
import { InvalidMessageError } from './InvalidMessageError';
import { PayloadPlaintext } from './payloads/PayloadPlaintext';
import { Recipient } from './Recipient';

const DEFAULT_TTL_SECONDS = 5 * 60; // 5 minutes

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
export abstract class RAMFMessage<Payload extends PayloadPlaintext> {
  public readonly id: string;
  public readonly creationDate: Date;
  public readonly ttl: number;
  public readonly senderCaCertificateChain: readonly Certificate[];

  constructor(
    readonly recipient: Recipient,
    readonly senderCertificate: Certificate,
    readonly payloadSerialized: Buffer,
    options: Partial<MessageOptions> = {},
  ) {
    this.id = options.id || uuid4();
    this.creationDate = setMilliseconds(options.creationDate ?? new Date(), 0);
    this.ttl = options.ttl !== undefined ? options.ttl : DEFAULT_TTL_SECONDS;

    this.senderCaCertificateChain =
      options.senderCaCertificateChain?.filter((c) => !c.isEqual(senderCertificate)) ?? [];
  }

  get expiryDate(): Date {
    const creationDateTimestamp = this.creationDate.getTime();
    return new Date(creationDateTimestamp + this.ttl * 1_000);
  }

  /**
   * Return RAMF serialization of message.
   *
   * @param senderPrivateKey
   * @param signatureOptions
   */
  public abstract serialize(
    // This method would be concrete if TS allowed us to store the message type and version as
    // properties
    senderPrivateKey: CryptoKey,
    signatureOptions?: Partial<SignatureOptions>,
  ): Promise<ArrayBuffer>;

  /**
   * Return certification path between sender's certificate and one certificate in
   * `trustedCertificates`.
   *
   * @param trustedCertificates
   */
  public async getSenderCertificationPath(
    trustedCertificates: readonly Certificate[],
  ): Promise<readonly Certificate[]> {
    return this.senderCertificate.getCertificationPath(
      this.senderCaCertificateChain,
      trustedCertificates,
    );
  }

  public async unwrapPayload(
    privateKeyOrStore: CryptoKey | PrivateKeyStore,
  ): Promise<PayloadUnwrapping<Payload>> {
    const payloadEnvelopedData = EnvelopedData.deserialize(bufferToArray(this.payloadSerialized));
    if (!(payloadEnvelopedData instanceof SessionEnvelopedData)) {
      throw new RAMFError('Sessionless payloads are no longer supported');
    }

    const payloadPlaintext = await this.decryptPayload(payloadEnvelopedData, privateKeyOrStore);
    const payload = await this.deserializePayload(payloadPlaintext);

    const senderSessionKey = await (
      payloadEnvelopedData as SessionEnvelopedData
    ).getOriginatorKey();

    return { payload, senderSessionKey };
  }

  /**
   * Report whether the message is valid.
   *
   * This doesn't check whether the sender is authorised.
   */
  public async validate(): Promise<null>;
  /**
   * Report whether the message is valid and the sender was authorised by one of the
   * `trustedCertificates`.
   *
   * @return The certification path from the sender to one of the `trustedCertificates`
   */
  public async validate(
    trustedCertificates: readonly Certificate[],
  ): Promise<readonly Certificate[]>;
  public async validate(
    trustedCertificates?: readonly Certificate[],
  ): Promise<readonly Certificate[] | null> {
    await this.validateTiming();

    if (trustedCertificates) {
      return this.validateAuthorization(trustedCertificates);
    }
    this.senderCertificate.validate();

    return null;
  }

  protected async decryptPayload(
    payloadEnvelopedData: EnvelopedData,
    privateKeyOrStore: CryptoKey | PrivateKeyStore,
  ): Promise<ArrayBuffer> {
    const privateKey = await this.fetchPrivateKey(payloadEnvelopedData, privateKeyOrStore);
    return payloadEnvelopedData.decrypt(privateKey);
  }

  protected async fetchPrivateKey(
    payloadEnvelopedData: EnvelopedData,
    privateKeyOrStore: CryptoKey | PrivateKeyStore,
  ): Promise<CryptoKey> {
    const keyId = payloadEnvelopedData.getRecipientKeyId();
    let privateKey: CryptoKey;
    if (privateKeyOrStore instanceof PrivateKeyStore) {
      const peerId = await this.senderCertificate.calculateSubjectId();
      privateKey = await privateKeyOrStore.retrieveSessionKey(keyId, this.recipient.id, peerId);
    } else {
      privateKey = privateKeyOrStore;
    }
    return privateKey;
  }

  protected abstract deserializePayload(payloadPlaintext: ArrayBuffer): Payload;

  private async validateAuthorization(
    trustedCertificates: readonly Certificate[],
  ): Promise<readonly Certificate[]> {
    let certificationPath: readonly Certificate[];
    try {
      certificationPath = await this.getSenderCertificationPath(trustedCertificates);
    } catch (error) {
      throw new InvalidMessageError(error as Error, 'Sender is not authorized');
    }

    const recipientCertificate = certificationPath[1];
    const recipientId = await recipientCertificate.calculateSubjectId();
    if (recipientId !== this.recipient.id) {
      throw new InvalidMessageError(`Sender is not authorized to reach ${this.recipient.id}`);
    }

    return certificationPath;
  }

  private async validateTiming(): Promise<void> {
    const currentDate = new Date();

    if (currentDate < this.creationDate) {
      throw new InvalidMessageError('Message date is in the future');
    }

    if (this.expiryDate < currentDate) {
      throw new InvalidMessageError('Message already expired');
    }
  }
}
