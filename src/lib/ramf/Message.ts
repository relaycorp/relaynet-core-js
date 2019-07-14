import bufferToArray from 'buffer-to-arraybuffer';
import { SmartBuffer } from 'smart-buffer';
import uuid4 from 'uuid4';
import { encrypt, EncryptionOptions } from '../cms';
import Certificate from '../pki/Certificate';
import Payload from './Payload';
import RAMFError from './RAMFError';

const MAX_RECIPIENT_ADDRESS_LENGTH = 2 ** 10 - 1;
const MAX_ID_LENGTH = 2 ** 8 - 1;
const MAX_DATE_TIMESTAMP_SEC = 2 ** 32;
const MAX_DATE_TIMESTAMP_MS = MAX_DATE_TIMESTAMP_SEC * 1_000 - 1;
const MAX_TTL = 2 ** 24 - 1;

const DEFAULT_TTL = 5 * 60; // 5 minutes

interface MessageOptions {
  readonly id: string;
  readonly date: Date;
  readonly ttl: number;
}

export default abstract class Message<PayloadSpecialization extends Payload> {
  public readonly id: string;
  public readonly date: Date;
  public readonly ttl: number;

  constructor(
    readonly recipientAddress: string,
    readonly senderCertificate: Certificate,
    readonly payload: PayloadSpecialization,
    options: Partial<MessageOptions> = {}
  ) {
    //region Recipient address
    if (MAX_RECIPIENT_ADDRESS_LENGTH < Buffer.byteLength(recipientAddress)) {
      throw new RAMFError('Recipient address exceeds maximum length');
    }
    //endregion

    //region Message id
    if (options.id && MAX_ID_LENGTH < options.id.length) {
      throw new RAMFError('Custom id exceeds maximum length');
    }
    this.id = options.id || uuid4();
    //endregion

    //region Date
    const customTimestampMs = options.date && options.date.getTime();
    if (customTimestampMs && customTimestampMs < 0) {
      throw new RAMFError('Date cannot be before Unix epoch');
    }
    if (customTimestampMs && MAX_DATE_TIMESTAMP_MS < customTimestampMs) {
      throw new RAMFError('Date timestamp cannot be represented with 32 bits');
    }
    this.date = customTimestampMs ? new Date(customTimestampMs) : new Date();
    //endregion

    //region TTL
    if (options.ttl && options.ttl < 0) {
      throw new RAMFError('TTL cannot be negative');
    }
    if (options.ttl && MAX_TTL < options.ttl) {
      throw new RAMFError('TTL must be less than 2^24');
    }
    this.ttl = Object.keys(options).includes('ttl')
      ? (options.ttl as number)
      : DEFAULT_TTL;
    //endregion
  }

  public async serialize(
    recipientCertificate: Certificate,
    encryptionOptions?: Partial<EncryptionOptions>
  ): Promise<ArrayBuffer> {
    const serialization = new SmartBuffer();

    //region File format signature
    serialization.writeString('Relaynet');
    serialization.writeUInt8(this.getConcreteMessageTypeOctet());
    serialization.writeUInt8(this.getConcreteMessageVersionOctet());
    //endregion

    //region Recipient address
    serialization.writeUInt16LE(Buffer.byteLength(this.recipientAddress));
    serialization.writeString(this.recipientAddress);
    //endregion

    //region Message id
    const messageId = this.id;
    serialization.writeInt8(messageId.length);
    serialization.writeString(messageId, 'ascii');
    //endregion

    //region Date
    serialization.writeUInt32LE(Math.floor(this.date.getTime() / 1_000));
    //endregion

    //region TTL
    const ttlBuffer = Buffer.allocUnsafe(3);
    ttlBuffer.writeUIntLE(this.ttl, 0, 3);
    serialization.writeBuffer(ttlBuffer);
    //endregion

    //region Payload
    const cmsEnvelopedData = await encrypt(
      this.payload.serialize(),
      recipientCertificate,
      encryptionOptions
    );
    serialization.writeUInt32LE(cmsEnvelopedData.byteLength);
    serialization.writeBuffer(Buffer.from(cmsEnvelopedData));
    //endregion

    return bufferToArray(serialization.toBuffer());
  }

  protected abstract getConcreteMessageTypeOctet(): number;

  protected abstract getConcreteMessageVersionOctet(): number;
}
