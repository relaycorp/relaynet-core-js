import { Parser } from 'binary-parser';
import bufferToArray from 'buffer-to-arraybuffer';
import { SmartBuffer } from 'smart-buffer';

import * as cmsSignedData from '../crypto_wrappers/cms/signedData';
import Message from '../messages/Message';
import RAMFSyntaxError from './RAMFSyntaxError';
import RAMFValidationError from './RAMFValidationError';

const MAX_MESSAGE_LENGTH = 9437184; // 9 MiB
const MAX_RECIPIENT_ADDRESS_LENGTH = 2 ** 10 - 1;
const MAX_ID_LENGTH = 2 ** 8 - 1;
const MAX_DATE_TIMESTAMP_SEC = 2 ** 32 - 1;
const MAX_TTL = 2 ** 24 - 1;
const MAX_PAYLOAD_LENGTH = 2 ** 23 - 1; // 8 MiB

const FORMAT_SIGNATURE_PARSER = new Parser()
  .endianess('little')
  .string('magic', { length: 8, assert: 'Relaynet' })
  .uint8('concreteMessageType')
  .uint8('concreteMessageVersion');

interface MessageFormatSignature {
  readonly concreteMessageType: number;
  readonly concreteMessageVersion: number;
}

const PARSER = new Parser()
  .endianess('little')
  .uint16('recipientAddressLength')
  .string('recipientAddress', { length: 'recipientAddressLength' })
  .uint8('idLength')
  .string('id', { length: 'idLength', encoding: 'ascii' })
  .uint32('dateTimestamp')
  .buffer('ttlBuffer', { length: 3 })
  .buffer('payloadLength', {
    // Ugly workaround for https://github.com/keichi/binary-parser/issues/33
    // @ts-ignore
    // tslint:disable-next-line:function-constructor
    formatter: new Function('buf', 'return buf.readUIntLE(0, 3)'),
    length: 3,
  })
  .buffer('payload', { length: 'payloadLength' });

export interface MessageFieldSet {
  readonly recipientAddress: string;
  readonly id: string;
  readonly dateTimestamp: number;
  readonly ttlBuffer: Buffer;
  readonly payload: Buffer;
}

/**
 * Sign and encode the current message.
 *
 * @param message The message to serialize.
 * @param concreteMessageTypeOctet
 * @param concreteMessageVersionOctet
 * @param senderPrivateKey The private key to sign the message.
 * @param signatureOptions Any signature options.
 */
export async function serialize(
  message: Message<any>,
  concreteMessageTypeOctet: number,
  concreteMessageVersionOctet: number,
  senderPrivateKey: CryptoKey,
  signatureOptions?: Partial<cmsSignedData.SignatureOptions>,
): Promise<ArrayBuffer> {
  //region Validation
  validateRecipientAddressLength(message.recipientAddress);
  validateMessageIdLength(message.id);
  validateDate(message.date);
  validateTtl(message.ttl);
  validatePayloadLength(message.payloadSerialized);
  //endregion

  //region File format signature
  const formatSignature = Buffer.allocUnsafe(10);
  formatSignature.write('Relaynet');
  formatSignature.writeUInt8(concreteMessageTypeOctet, 8);
  formatSignature.writeUInt8(concreteMessageVersionOctet, 9);
  //endregion

  const fieldSetSerialization = new SmartBuffer();

  //region Recipient address
  fieldSetSerialization.writeUInt16LE(Buffer.byteLength(message.recipientAddress));
  fieldSetSerialization.writeString(message.recipientAddress);
  //endregion

  //region Message id
  const messageId = message.id;
  fieldSetSerialization.writeUInt8(messageId.length);
  fieldSetSerialization.writeString(messageId, 'ascii');
  //endregion

  //region Date
  fieldSetSerialization.writeUInt32LE(dateToTimestamp(message.date));
  //endregion

  //region TTL
  const ttlBuffer = Buffer.allocUnsafe(3);
  ttlBuffer.writeUIntLE(message.ttl, 0, 3);
  fieldSetSerialization.writeBuffer(ttlBuffer);
  //endregion

  //region Payload
  const payloadLength = Buffer.allocUnsafe(3);
  payloadLength.writeUIntLE(message.payloadSerialized.byteLength, 0, 3);
  const payloadSerialized = Buffer.from(message.payloadSerialized);
  fieldSetSerialization.writeBuffer(payloadLength);
  fieldSetSerialization.writeBuffer(payloadSerialized);
  //endregion

  const serializationBeforeSignature = fieldSetSerialization.toBuffer();

  //region Signature
  const signature = await cmsSignedData.sign(
    bufferToArray(serializationBeforeSignature),
    senderPrivateKey,
    message.senderCertificate,
    message.senderCaCertificateChain,
    signatureOptions,
  );
  //endregion

  // There doesn't seem to be an efficient way to concatenate ArrayBuffer instances, so we'll have
  // to make a copy of the signature (which already contains a copy of the payload). So by the end
  // of this function we'll need more than 3x the size of the payload in memory. This issue will
  // go away with https://github.com/relaynet/specs/issues/14
  const serialization = Buffer.concat([formatSignature, new Uint8Array(signature)]);
  return bufferToArray(serialization);
}

function validateMessageLength(serialization: ArrayBuffer): void {
  if (MAX_MESSAGE_LENGTH < serialization.byteLength) {
    throw new RAMFSyntaxError(
      `Message should not be longer than 9 MiB (got ${serialization.byteLength} octets)`,
    );
  }
}

export async function deserialize<M extends Message<any>>(
  serialization: ArrayBuffer,
  concreteMessageTypeOctet: number,
  concreteMessageVersionOctet: number,
  messageClass: new (...args: readonly any[]) => M,
): Promise<M> {
  validateMessageLength(serialization);
  const messageFormatSignature = parseMessageFormatSignature(serialization.slice(0, 10));
  validateFileFormatSignature(
    messageFormatSignature,
    concreteMessageTypeOctet,
    concreteMessageVersionOctet,
  );

  const signatureVerification = await verifySignature(serialization.slice(10));

  const messageFields = parseMessageFields(signatureVerification.plaintext);
  validateRecipientAddressLength(messageFields.recipientAddress);
  validatePayloadLength(messageFields.payload);

  validateMessageTiming(messageFields, signatureVerification);

  return new messageClass(
    messageFields.recipientAddress,
    signatureVerification.signerCertificate,
    messageFields.payload,
    {
      date: new Date(messageFields.dateTimestamp * 1_000),
      id: messageFields.id,
      senderCaCertificateChain: signatureVerification.attachedCertificates,
      ttl: messageFields.ttlBuffer.readUIntLE(0, 3),
    },
  );
}

function decimalToHex(numberDecimal: number): string {
  return '0x' + numberDecimal.toString(16);
}

function dateToTimestamp(date: Date): number {
  return Math.floor(date.getTime() / 1_000);
}

//region Serialization and deserialization validation

function validateFileFormatSignature(
  messageFields: MessageFormatSignature,
  concreteMessageTypeOctet: number,
  concreteMessageVersionOctet: number,
): void {
  //region Message type validation
  if (messageFields.concreteMessageType !== concreteMessageTypeOctet) {
    const expectedMessageTypeHex = decimalToHex(concreteMessageTypeOctet);
    const actualMessageTypeHex = decimalToHex(messageFields.concreteMessageType);
    throw new RAMFSyntaxError(
      `Expected concrete message type ${expectedMessageTypeHex} but got ${actualMessageTypeHex}`,
    );
  }
  //endregion

  //region Message version validation
  if (messageFields.concreteMessageVersion !== concreteMessageVersionOctet) {
    const expectedVersionHex = decimalToHex(concreteMessageVersionOctet);
    const actualVersionHex = decimalToHex(messageFields.concreteMessageVersion);
    throw new RAMFSyntaxError(
      `Expected concrete message version ${expectedVersionHex} but got ${actualVersionHex}`,
    );
  }
  //endregion
}

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

function validatePayloadLength(payloadBuffer: ArrayBuffer): void {
  const length = payloadBuffer.byteLength;
  if (MAX_PAYLOAD_LENGTH < length) {
    throw new RAMFSyntaxError(`Payload size must not exceed 8 MiB (got ${length} octets)`);
  }
}

//endregion

//region Deserialization validation

function parseMessageFormatSignature(serialization: ArrayBuffer): MessageFormatSignature {
  try {
    return FORMAT_SIGNATURE_PARSER.parse(Buffer.from(serialization));
  } catch (error) {
    throw new RAMFSyntaxError(error, 'Serialization starts with invalid RAMF format signature');
  }
}

function parseMessageFields(serialization: ArrayBuffer): MessageFieldSet {
  try {
    return PARSER.parse(Buffer.from(serialization));
  } catch (error) {
    throw new RAMFSyntaxError(error, 'CMS SignedData value contains invalid field set');
  }
}

async function verifySignature(
  cmsSignedDataSerialized: ArrayBuffer,
): Promise<cmsSignedData.SignatureVerification> {
  try {
    return await cmsSignedData.verifySignature(cmsSignedDataSerialized);
  } catch (error) {
    throw new RAMFValidationError(error, 'Invalid RAMF message signature');
  }
}

function validateMessageTiming(
  messageFields: MessageFieldSet,
  signatureVerification: cmsSignedData.SignatureVerification,
): void {
  const currentTimestamp = dateToTimestamp(new Date());
  if (currentTimestamp < messageFields.dateTimestamp) {
    throw new RAMFValidationError('Message date is in the future');
  }

  const pkijsCertificate = signatureVerification.signerCertificate.pkijsCertificate;
  if (messageFields.dateTimestamp < dateToTimestamp(pkijsCertificate.notBefore.value)) {
    throw new RAMFValidationError('Message was created before the sender certificate was valid');
  }

  if (dateToTimestamp(pkijsCertificate.notAfter.value) < messageFields.dateTimestamp) {
    throw new RAMFValidationError('Message was created after the sender certificate expired');
  }

  const ttl = messageFields.ttlBuffer.readUIntLE(0, 3);
  const expiryTimestamp = messageFields.dateTimestamp + ttl;
  if (expiryTimestamp < currentTimestamp) {
    throw new RAMFValidationError('Message already expired');
  }
}

//endregion
