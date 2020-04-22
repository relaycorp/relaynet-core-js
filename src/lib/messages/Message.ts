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
  readonly date: Date;
  readonly ttl: number;
  readonly senderCaCertificateChain: readonly Certificate[];
}

/**
 * Relaynet Abstract Message Format, version 1.
 */
export default abstract class Message<Payload extends PayloadPlaintext> {
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

  get expiryDate(): Date {
    const creationDateTimestamp = this.date.getTime();
    return new Date(creationDateTimestamp + this.ttl * 1_000);
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
    signatureOptions?: SignatureOptions,
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
    keyStore: PrivateKeyStore,
  ): Promise<{ readonly payload: Payload; readonly senderSessionKey?: OriginatorSessionKey }> {
    const payloadEnvelopedData = EnvelopedData.deserialize(bufferToArray(this.payloadSerialized));

    const payloadPlaintext = await this.decryptPayload(payloadEnvelopedData, keyStore);
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
    if (trustedCertificates) {
      await this.validateAuthorization(trustedCertificates);
    }
  }

  protected async decryptPayload(
    payloadEnvelopedData: EnvelopedData,
    keyStore: PrivateKeyStore,
  ): Promise<ArrayBuffer> {
    const keyId = payloadEnvelopedData.getRecipientKeyId();
    const privateKey =
      payloadEnvelopedData instanceof SessionEnvelopedData
        ? await keyStore.fetchSessionKey(keyId, this.senderCertificate)
        : (await keyStore.fetchNodeKey(keyId)).privateKey;
    return payloadEnvelopedData.decrypt(privateKey);
  }

  protected abstract deserializePayload(payloadPlaintext: ArrayBuffer): Payload;

  protected async validateAuthorization(
    trustedCertificates: readonly Certificate[],
  ): Promise<void> {
    // tslint:disable-next-line:no-let
    let certificationPath: readonly Certificate[];
    try {
      certificationPath = await this.getSenderCertificationPath(trustedCertificates);
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
