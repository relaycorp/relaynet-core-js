import bufferToArray from 'buffer-to-arraybuffer';
import uuid4 from 'uuid4';

import {
  EnvelopedData,
  OriginatorSessionKey,
  SessionEnvelopedData,
} from '../crypto_wrappers/cms/envelopedData';
import { SignatureOptions } from '../crypto_wrappers/cms/signedData';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { PrivateKeyStore } from '../keyStores/privateKeyStore';
import InvalidMessageError from './InvalidMessageError';
import PayloadPlaintext from './payloads/PayloadPlaintext';

const DEFAULT_TTL_SECONDS = 5 * 60; // 5 minutes

interface MessageOptions {
  readonly id: string;
  readonly creationDate: Date;
  readonly ttl: number;
  readonly senderCaCertificateChain: readonly Certificate[];
}

/**
 * Relaynet Abstract Message Format, version 1.
 */
export default abstract class RAMFMessage<Payload extends PayloadPlaintext> {
  public readonly id: string;
  public readonly creationDate: Date;
  public readonly ttl: number;
  public readonly senderCaCertificateChain: readonly Certificate[];

  constructor(
    readonly recipientAddress: string,
    readonly senderCertificate: Certificate,
    readonly payloadSerialized: Buffer,
    options: Partial<MessageOptions> = {},
  ) {
    this.id = options.id || uuid4();
    this.creationDate = options.creationDate || new Date();
    this.ttl = options.ttl !== undefined ? options.ttl : DEFAULT_TTL_SECONDS;

    this.senderCaCertificateChain =
      options.senderCaCertificateChain?.filter((c) => !c.isEqual(senderCertificate)) ?? [];
  }

  get expiryDate(): Date {
    const creationDateTimestamp = this.creationDate.getTime();
    return new Date(creationDateTimestamp + this.ttl * 1_000);
  }

  get isRecipientAddressPrivate(): boolean {
    try {
      // tslint:disable-next-line:no-unused-expression
      new URL(this.recipientAddress);
    } catch (_) {
      return true;
    }
    return false;
  }

  /**
   * Return RAMF serialization of message.
   *
   * @param senderPrivateKey
   * @param signatureOptions
   */
  public abstract async serialize(
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
  ): Promise<{ readonly payload: Payload; readonly senderSessionKey?: OriginatorSessionKey }> {
    const payloadEnvelopedData = EnvelopedData.deserialize(bufferToArray(this.payloadSerialized));

    const payloadPlaintext = await this.decryptPayload(payloadEnvelopedData, privateKeyOrStore);
    const payload = await this.deserializePayload(payloadPlaintext);

    const senderSessionKey =
      payloadEnvelopedData instanceof SessionEnvelopedData
        ? await payloadEnvelopedData.getOriginatorKey()
        : undefined;

    return { payload, senderSessionKey };
  }

  /**
   * Report whether the message is valid.
   *
   * @param trustedCertificates If present, will check that the sender is authorized to send
   *   the message based on the trusted certificates.
   */
  public async validate(trustedCertificates?: readonly Certificate[]): Promise<void> {
    await this.validateTiming();

    if (trustedCertificates) {
      await this.validateAuthorization(trustedCertificates);
    }
  }

  protected async decryptPayload(
    payloadEnvelopedData: EnvelopedData,
    privateKeyOrStore: CryptoKey | PrivateKeyStore,
  ): Promise<ArrayBuffer> {
    const keyId = payloadEnvelopedData.getRecipientKeyId();
    const privateKey = await this.fetchPrivateKey(payloadEnvelopedData, privateKeyOrStore, keyId);
    return payloadEnvelopedData.decrypt(privateKey);
  }

  protected async fetchPrivateKey(
    payloadEnvelopedData: EnvelopedData,
    privateKeyOrStore: CryptoKey | PrivateKeyStore,
    keyId: Buffer,
  ): Promise<CryptoKey> {
    // tslint:disable-next-line:no-let
    let privateKey: CryptoKey;
    if (privateKeyOrStore instanceof PrivateKeyStore) {
      privateKey =
        payloadEnvelopedData instanceof SessionEnvelopedData
          ? await privateKeyOrStore.fetchSessionKey(keyId, this.senderCertificate)
          : (await privateKeyOrStore.fetchNodeKey(keyId)).privateKey;
    } else {
      privateKey = privateKeyOrStore;
    }
    return privateKey;
  }

  protected abstract deserializePayload(payloadPlaintext: ArrayBuffer): Payload;

  private async validateAuthorization(trustedCertificates: readonly Certificate[]): Promise<void> {
    // tslint:disable-next-line:no-let
    let certificationPath: readonly Certificate[];
    try {
      certificationPath = await this.getSenderCertificationPath(trustedCertificates);
    } catch (error) {
      throw new InvalidMessageError(error, 'Sender is not authorized');
    }

    if (!this.isRecipientAddressPrivate) {
      return;
    }

    const recipientCertificate = certificationPath[1];
    const recipientPrivateAddress = await recipientCertificate.calculateSubjectPrivateAddress();
    if (recipientPrivateAddress !== this.recipientAddress) {
      throw new InvalidMessageError(`Sender is not authorized to reach ${this.recipientAddress}`);
    }
  }

  private async validateTiming(): Promise<void> {
    const currentDate = new Date();
    currentDate.setMilliseconds(0); // Round down to match precision of date field

    if (currentDate < this.creationDate) {
      throw new InvalidMessageError('Message date is in the future');
    }

    const pkijsCertificate = this.senderCertificate.pkijsCertificate;
    if (this.creationDate < pkijsCertificate.notBefore.value) {
      throw new InvalidMessageError('Message was created before the sender certificate was valid');
    }

    if (pkijsCertificate.notAfter.value < this.creationDate) {
      throw new InvalidMessageError('Message was created after the sender certificate expired');
    }

    const expiryDate = new Date(this.creationDate);
    expiryDate.setSeconds(expiryDate.getSeconds() + this.ttl);
    if (expiryDate < currentDate) {
      throw new InvalidMessageError('Message already expired');
    }
  }
}
