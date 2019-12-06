import { Parser } from 'binary-parser';
import bufferToArray from 'buffer-to-arraybuffer';
import { SmartBuffer } from 'smart-buffer';

import * as cms from '../cms';
import Certificate from '../pki/Certificate';
import Message from './Message';
import RAMFSyntaxError from './RAMFSyntaxError';
import RAMFValidationError from './RAMFValidationError';

const MAX_RECIPIENT_ADDRESS_LENGTH = 2 ** 10 - 1;
const MAX_ID_LENGTH = 2 ** 8 - 1;
const MAX_DATE_TIMESTAMP_SEC = 2 ** 32 - 1;
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
export interface MessageFields {
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
    options?: Partial<cms.EncryptionOptions | cms.SignatureOptions>
  ): Promise<ArrayBuffer> {
    //region Validation
    validateRecipientAddressLength(message.recipientAddress);
    validateMessageIdLength(message.id);
    validateDate(message.date);
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
    serialization.writeUInt32LE(dateToTimestamp(message.date));
    //endregion

    //region TTL
    const ttlBuffer = Buffer.allocUnsafe(3);
    ttlBuffer.writeUIntLE(message.ttl, 0, 3);
    serialization.writeBuffer(ttlBuffer);
    //endregion

    //region Payload
    const cmsEnvelopedData = await cms.encrypt(
      message.exportPayload(),
      recipientCertificate,
      options as cms.EncryptionOptions
    );
    serialization.writeUInt32LE(cmsEnvelopedData.byteLength);
    serialization.writeBuffer(Buffer.from(cmsEnvelopedData));
    //endregion

    const serializationBeforeSignature = serialization.toBuffer();

    //region Signature
    const signature = await cms.sign(
      bufferToArray(serializationBeforeSignature),
      senderPrivateKey,
      message.senderCertificate,
      new Set([message.senderCertificate, ...message.senderCertificateChain]),
      options as cms.SignatureOptions
    );
    validateSignatureLength(signature);
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
    //region Parse and validate syntax
    const messageFields = parseMessage(serialization);

    this.validateFileFormatSignature(messageFields);
    validateRecipientAddressLength(messageFields.recipientAddress);
    validateSignatureLength(messageFields.signature);
    //endregion

    //region Post-deserialization validation
    const signatureVerification = await verifySignature(serialization, messageFields);

    validateMessageTiming(messageFields, signatureVerification);
    //endregion

    const payloadPlaintext = await cms.decrypt(
      bufferToArray(messageFields.payload),
      recipientPrivateKey
    );

    return new this.messageClass(
      messageFields.recipientAddress,
      signatureVerification.signerCertificate,
      payloadPlaintext,
      {
        date: new Date(messageFields.dateTimestamp * 1_000),
        id: messageFields.id,
        senderCertificateChain: signatureVerification.signerCertificateChain,
        ttl: messageFields.ttlBuffer.readUIntLE(0, 3)
      }
    );
  }

  private validateFileFormatSignature(messageFields: MessageFields): void {
    //region Message type validation
    if (messageFields.concreteMessageType !== this.concreteMessageTypeOctet) {
      const expectedMessageTypeHex = decimalToHex(this.concreteMessageTypeOctet);
      const actualMessageTypeHex = decimalToHex(messageFields.concreteMessageType);
      throw new RAMFSyntaxError(
        `Expected concrete message type ${expectedMessageTypeHex} but got ${actualMessageTypeHex}`
      );
    }
    //endregion

    //region Message version validation
    if (messageFields.concreteMessageVersion !== this.concreteMessageVersionOctet) {
      const expectedVersionHex = decimalToHex(this.concreteMessageVersionOctet);
      const actualVersionHex = decimalToHex(messageFields.concreteMessageVersion);
      throw new RAMFSyntaxError(
        `Expected concrete message version ${expectedVersionHex} but got ${actualVersionHex}`
      );
    }
    //endregion
  }
}

function decimalToHex(numberDecimal: number): string {
  return '0x' + numberDecimal.toString(16);
}

function dateToTimestamp(date: Date): number {
  return Math.floor(date.getTime() / 1_000);
}

//region Serialization and deserialization validation

function validateRecipientAddressLength(recipientAddress: string): void {
  if (MAX_RECIPIENT_ADDRESS_LENGTH < Buffer.byteLength(recipientAddress)) {
    throw new RAMFSyntaxError('Recipient address exceeds maximum length');
  }
}

function validateMessageIdLength(messageId: string): void {
  if (MAX_ID_LENGTH < messageId.length) {
    throw new RAMFSyntaxError('Custom id exceeds maximum length');
  }
}

function validateDate(date: Date): void {
  const timestamp = dateToTimestamp(date);
  if (timestamp < 0) {
    throw new RAMFSyntaxError('Date cannot be before Unix epoch');
  }
  if (MAX_DATE_TIMESTAMP_SEC < timestamp) {
    throw new RAMFSyntaxError('Date timestamp cannot be represented with 32 bits');
  }
}

function validateTtl(ttl: number): void {
  if (ttl < 0) {
    throw new RAMFSyntaxError('TTL cannot be negative');
  }
  if (MAX_TTL < ttl) {
    throw new RAMFSyntaxError('TTL must be less than 2^24');
  }
}

function validateSignatureLength(signatureBuffer: ArrayBuffer): void {
  const signatureLength = signatureBuffer.byteLength;
  if (MAX_SIGNATURE_LENGTH < signatureLength) {
    throw new RAMFSyntaxError(
      `Signature length is ${signatureLength} but maximum is ${MAX_SIGNATURE_LENGTH}`
    );
  }
}

//endregion

//region Deserialization validation

function parseMessage(serialization: ArrayBuffer): MessageFields {
  try {
    return PARSER.parse(Buffer.from(serialization));
  } catch (error) {
    throw new RAMFSyntaxError(error, 'Serialization is not a valid RAMF message');
  }
}

async function verifySignature(
  messageSerialized: ArrayBuffer,
  messageFields: MessageFields
): Promise<cms.SignatureVerification> {
  const signatureCiphertext = bufferToArray(messageFields.signature);
  const signatureCiphertextLengthWithLengthPrefix = 2 + signatureCiphertext.byteLength;
  const signaturePlaintext = messageSerialized.slice(
    0,
    messageSerialized.byteLength - signatureCiphertextLengthWithLengthPrefix
  );
  try {
    return (await cms.verifySignature(
      signatureCiphertext,
      signaturePlaintext
    )) as cms.SignatureVerification;
  } catch (error) {
    throw new RAMFValidationError('Invalid RAMF message signature', messageFields, error);
  }
}

function validateMessageTiming(
  messageFields: MessageFields,
  signatureVerification: cms.SignatureVerification
): void {
  const currentTimestamp = dateToTimestamp(new Date());
  if (currentTimestamp < messageFields.dateTimestamp) {
    throw new RAMFValidationError('Message date is in the future', messageFields);
  }

  const pkijsCertificate = signatureVerification.signerCertificate.pkijsCertificate;
  if (messageFields.dateTimestamp < dateToTimestamp(pkijsCertificate.notBefore.value)) {
    throw new RAMFValidationError(
      'Message was created before the sender certificate was valid',
      messageFields
    );
  }

  if (dateToTimestamp(pkijsCertificate.notAfter.value) < messageFields.dateTimestamp) {
    throw new RAMFValidationError(
      'Message was created after the sender certificate expired',
      messageFields
    );
  }

  const ttl = messageFields.ttlBuffer.readUIntLE(0, 3);
  const expiryTimestamp = messageFields.dateTimestamp + ttl;
  if (expiryTimestamp < currentTimestamp) {
    throw new RAMFValidationError('Message already expired', messageFields);
  }
}

//endregion
