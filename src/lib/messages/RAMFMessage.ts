import bufferToArray from 'buffer-to-arraybuffer';
import uuid4 from 'uuid4';

import { makeDateWithSecondPrecision } from '../_utils';
import { EnvelopedData, SessionEnvelopedData } from '../crypto_wrappers/cms/envelopedData';
import { SignatureOptions } from '../crypto_wrappers/cms/SignatureOptions';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { PrivateKeyStore } from '../keyStores/privateKeyStore';
import RAMFError from '../ramf/RAMFError';
import { SessionKey } from '../SessionKey';
import InvalidMessageError from './InvalidMessageError';
import PayloadPlaintext from './payloads/PayloadPlaintext';
import { RecipientAddressType } from './RecipientAddressType';

const DEFAULT_TTL_SECONDS = 5 * 60; // 5 minutes

const PRIVATE_ADDRESS_REGEX = /^0[a-f0-9]+$/;

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
    this.creationDate = makeDateWithSecondPrecision(options.creationDate);
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
  ): Promise<{ readonly payload: Payload; readonly senderSessionKey: SessionKey }> {
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
   * @param recipientAddressType The expected type of recipient address, if one is required
   * @param trustedCertificates If present, will check that the sender is authorized to send
   *   the message based on the trusted certificates.
   * @return The certification path from the sender to one of the `trustedCertificates` (if present)
   */
  public async validate(
    recipientAddressType?: RecipientAddressType,
    trustedCertificates?: readonly Certificate[],
  ): Promise<readonly Certificate[] | null> {
    await this.validateRecipientAddress(recipientAddressType);

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
      const peerPrivateAddress = await this.senderCertificate.calculateSubjectPrivateAddress();
      privateKey = await privateKeyOrStore.fetchSessionKey(keyId, peerPrivateAddress);
    } else {
      privateKey = privateKeyOrStore;
    }
    return privateKey;
  }

  protected abstract deserializePayload(payloadPlaintext: ArrayBuffer): Payload;

  private async validateRecipientAddress(
    requiredRecipientAddressType?: RecipientAddressType,
  ): Promise<void> {
    const isAddressPrivate = this.isRecipientAddressPrivate;
    if (isAddressPrivate && !PRIVATE_ADDRESS_REGEX[Symbol.match](this.recipientAddress)) {
      throw new InvalidMessageError('Recipient address is malformed');
    }

    if (requiredRecipientAddressType === RecipientAddressType.PUBLIC && isAddressPrivate) {
      throw new InvalidMessageError('Recipient address should be public but got a private one');
    }
    if (requiredRecipientAddressType === RecipientAddressType.PRIVATE && !isAddressPrivate) {
      throw new InvalidMessageError('Recipient address should be private but got a public one');
    }
  }

  private async validateAuthorization(
    trustedCertificates: readonly Certificate[],
  ): Promise<readonly Certificate[]> {
    let certificationPath: readonly Certificate[];
    try {
      certificationPath = await this.getSenderCertificationPath(trustedCertificates);
    } catch (error) {
      throw new InvalidMessageError(error, 'Sender is not authorized');
    }

    if (this.isRecipientAddressPrivate) {
      const recipientCertificate = certificationPath[1];
      const recipientPrivateAddress = await recipientCertificate.calculateSubjectPrivateAddress();
      if (recipientPrivateAddress !== this.recipientAddress) {
        throw new InvalidMessageError(`Sender is not authorized to reach ${this.recipientAddress}`);
      }
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
