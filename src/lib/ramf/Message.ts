import bufferToArray from 'buffer-to-arraybuffer';
import { SmartBuffer } from 'smart-buffer';
import uuid4 from 'uuid4';
import Certificate from '../pki/Certificate';
import Payload from './Payload';
import RAMFError from './RAMFError';

const MAX_RECIPIENT_ADDRESS_LENGTH = 2 ** 10 - 1;
const MAX_ID_LENGTH = 2 ** 8 - 1;
const MAX_DATE_TIMESTAMP_SEC = 2 ** 32;
const MAX_DATE_TIMESTAMP_MS = MAX_DATE_TIMESTAMP_SEC * 1_000 - 1;

interface MessageOptions {
  readonly id: string;
  readonly date: Date;
}

export default abstract class Message {
  public readonly id: string;
  public readonly date: Date;

  constructor(
    readonly recipientAddress: string,
    readonly senderCertificate: Certificate,
    readonly payload: Payload,
    options: Partial<MessageOptions> = {}
  ) {
    if (MAX_RECIPIENT_ADDRESS_LENGTH < recipientAddress.length) {
      throw new RAMFError('Recipient address exceeds maximum length');
    }

    if (options.id && MAX_ID_LENGTH < options.id.length) {
      throw new RAMFError('Custom id exceeds maximum length');
    }
    this.id = options.id || uuid4();

    const customTimestampMs = options.date && options.date.getTime();
    if (customTimestampMs && customTimestampMs < 0) {
      throw new RAMFError('Date cannot be before Unix epoch');
    }
    if (customTimestampMs && MAX_DATE_TIMESTAMP_MS < customTimestampMs) {
      throw new RAMFError('Date timestamp cannot be represented with 32 bits');
    }
    this.date = customTimestampMs ? new Date(customTimestampMs) : new Date();
  }

  public async serialize(): Promise<ArrayBuffer> {
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

    return bufferToArray(serialization.toBuffer());
  }

  protected abstract getConcreteMessageTypeOctet(): number;

  protected abstract getConcreteMessageVersionOctet(): number;
}
