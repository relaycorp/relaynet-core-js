import { Parser } from 'binary-parser';
import bufferToArray from 'buffer-to-arraybuffer';
import { SmartBuffer } from 'smart-buffer';

import { decrypt, encrypt, EncryptionOptions, sign, SignatureOptions } from '../cms';
import Certificate from '../pki/Certificate';
import Message from './Message';
import RAMFError from './RAMFError';

const MAX_RECIPIENT_ADDRESS_LENGTH = 2 ** 10 - 1;
const MAX_ID_LENGTH = 2 ** 8 - 1;
const MAX_DATE_TIMESTAMP_SEC = 2 ** 32;
const MAX_DATE_TIMESTAMP_MS = MAX_DATE_TIMESTAMP_SEC * 1_000 - 1;
const MAX_TTL = 2 ** 24 - 1;
const MAX_SIGNATURE_LENGTH = 2 ** 14 - 1;

const PARSER = new Parser()
  .endianess('little')
  .string('magic', { length: 8, assert: 'Relaynet' })
  .uint8('concreteMessageType')
  .uint8('concreteMessageVersion')
  .uint16('recipientAddressLength')
  .string('recipientAddress', { length: 'recipientAddressLength' })
  .uint8('idLength')
  .string('id', { length: 'idLength', encoding: 'ascii' })
  .uint32('dateTimestamp')
  .buffer('ttlBuffer', { length: 3 })
  .uint32('payloadLength')
  .buffer('payload', { length: 'payloadLength' })
  .uint16('signatureLength')
  .buffer('signature', { length: 'signatureLength' });
interface MessageFields {
  readonly concreteMessageType: number;
  readonly concreteMessageVersion: number;
  readonly recipientAddress: string;
  readonly id: string;
  readonly dateTimestamp: number;
  readonly ttlBuffer: Buffer;
  readonly payload: Buffer;
  readonly signature: Buffer;
}

export class MessageSerializer<MessageSpecialization extends Message> {
  // Ideally, the members of this class would be part of `Message`, but TS
  // doesn't support static abstract members:
  // https://github.com/microsoft/TypeScript/issues/34516

  constructor(
    protected readonly messageClass: new (...args: readonly any[]) => MessageSpecialization,
    readonly concreteMessageTypeOctet: number,
    readonly concreteMessageVersionOctet: number
  ) {}

  /**
   * Encrypt, sign and encode the current message.
   *
   * @param message The message to serialize.
   * @param senderPrivateKey The private key to sign the message.
   * @param recipientCertificate The certificate whose public key is to be used
   *   to encrypt the payload.
   * @param options Any encryption/signature options.
   */
  public async serialize(
    message: MessageSpecialization,
    senderPrivateKey: CryptoKey,
    recipientCertificate: Certificate,
    options?: Partial<EncryptionOptions | SignatureOptions>
  ): Promise<ArrayBuffer> {
    //region Validation
    validateRecipientAddressLength(message.recipientAddress);
    validateMessageIdLength(message.id);
    validateDate(message.date.getTime());
    validateTtl(message.ttl);
    //endregion

    const serialization = new SmartBuffer();

    //region File format signature
    serialization.writeString('Relaynet');
    serialization.writeUInt8(this.concreteMessageTypeOctet);
    serialization.writeUInt8(this.concreteMessageVersionOctet);
    //endregion

    //region Recipient address
    serialization.writeUInt16LE(Buffer.byteLength(message.recipientAddress));
    serialization.writeString(message.recipientAddress);
    //endregion

    //region Message id
    const messageId = message.id;
    serialization.writeUInt8(messageId.length);
    serialization.writeString(messageId, 'ascii');
    //endregion

    //region Date
    serialization.writeUInt32LE(Math.floor(message.date.getTime() / 1_000));
    //endregion

    //region TTL
    const ttlBuffer = Buffer.allocUnsafe(3);
    ttlBuffer.writeUIntLE(message.ttl, 0, 3);
    serialization.writeBuffer(ttlBuffer);
    //endregion

    //region Payload
    const cmsEnvelopedData = await encrypt(
      message.exportPayload(),
      recipientCertificate,
      options as EncryptionOptions
    );
    serialization.writeUInt32LE(cmsEnvelopedData.byteLength);
    serialization.writeBuffer(Buffer.from(cmsEnvelopedData));
    //endregion

    const serializationBeforeSignature = serialization.toBuffer();

    //region Signature
    const signature = await sign(
      bufferToArray(serializationBeforeSignature),
      senderPrivateKey,
      message.senderCertificate,
      new Set([message.senderCertificate, ...message.senderCertificateChain]),
      options as SignatureOptions
    );
    if (MAX_SIGNATURE_LENGTH < signature.byteLength) {
      throw new RAMFError('Resulting signature must be less than 16 KiB');
    }
    const signatureLengthPrefix = Buffer.allocUnsafe(2);
    signatureLengthPrefix.writeUInt16LE(signature.byteLength, 0);
    //endregion

    const finalSerialization = Buffer.concat([
      serializationBeforeSignature,
      signatureLengthPrefix,
      Buffer.from(signature)
    ]);
    return bufferToArray(finalSerialization);
  }

  public async deserialize(
    serialization: ArrayBuffer,
    recipientPrivateKey: CryptoKey
  ): Promise<MessageSpecialization> {
    const messageParts = parseMessage(serialization);

    this.validateMessageFields(messageParts);

    const payloadPlaintext = await decrypt(
      bufferToArray(messageParts.payload),
      recipientPrivateKey
    );

    return new this.messageClass(messageParts.recipientAddress, undefined, payloadPlaintext, {
      date: new Date(messageParts.dateTimestamp * 1_000),
      id: messageParts.id,
      ttl: messageParts.ttlBuffer.readUIntLE(0, 3)
    });
  }

  private validateMessageFields(messageFields: MessageFields): void {
    //region Message type validation
    if (messageFields.concreteMessageType !== this.concreteMessageTypeOctet) {
      const expectedMessageTypeHex = decimalToHex(this.concreteMessageTypeOctet);
      const actualMessageTypeHex = decimalToHex(messageFields.concreteMessageType);
      throw new RAMFError(
        `Expected concrete message type ${expectedMessageTypeHex} but got ${actualMessageTypeHex}`
      );
    }
    //endregion

    //region Message version validation
    if (messageFields.concreteMessageVersion !== this.concreteMessageVersionOctet) {
      const expectedVersionHex = decimalToHex(this.concreteMessageVersionOctet);
      const actualVersionHex = decimalToHex(messageFields.concreteMessageVersion);
      throw new RAMFError(
        `Expected concrete message version ${expectedVersionHex} but got ${actualVersionHex}`
      );
    }
    //endregion

    validateRecipientAddressLength(messageFields.recipientAddress);
  }
}

function parseMessage(serialization: ArrayBuffer): MessageFields {
  try {
    return PARSER.parse(Buffer.from(serialization));
  } catch (error) {
    throw new RAMFError(error, 'Serialization is not a valid RAMF message');
  }
}

function decimalToHex(numberDecimal: number): string {
  return '0x' + numberDecimal.toString(16);
}

//region Validation

function validateRecipientAddressLength(recipientAddress: string): void {
  if (MAX_RECIPIENT_ADDRESS_LENGTH < Buffer.byteLength(recipientAddress)) {
    throw new RAMFError('Recipient address exceeds maximum length');
  }
}

function validateMessageIdLength(messageId: string): void {
  if (MAX_ID_LENGTH < messageId.length) {
    throw new RAMFError('Custom id exceeds maximum length');
  }
}

function validateDate(timestampMs: number): void {
  if (timestampMs < 0) {
    throw new RAMFError('Date cannot be before Unix epoch');
  }
  if (MAX_DATE_TIMESTAMP_MS < timestampMs) {
    throw new RAMFError('Date timestamp cannot be represented with 32 bits');
  }
}

function validateTtl(ttl: number): void {
  if (ttl < 0) {
    throw new RAMFError('TTL cannot be negative');
  }
  if (MAX_TTL < ttl) {
    throw new RAMFError('TTL must be less than 2^24');
  }
}

//endregion
