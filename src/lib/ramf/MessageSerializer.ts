import { Parser } from 'binary-parser';
import bufferToArray from 'buffer-to-arraybuffer';
import { SmartBuffer } from 'smart-buffer';

import { encrypt, EncryptionOptions, sign, SignatureOptions } from '../cms';
import Certificate from '../pki/Certificate';
import * as field_validators from './_field_validators';
import Message from './Message';
import RAMFError from './RAMFError';

const MAX_SIGNATURE_LENGTH = 2 ** 14 - 1;

const PARSER = new Parser()
  .endianess('little')
  .string('magic', { length: 8, assert: 'Relaynet' })
  .uint8('concreteMessageType')
  .uint8('concreteMessageVersion')
  .uint16('recipientAddressLength')
  .string('recipientAddress', { length: 'recipientAddressLength' });
interface MessageParts {
  readonly magic: string;
  readonly concreteMessageType: number;
  readonly concreteMessageVersion: number;
  readonly recipientAddressLength: number;
  readonly recipientAddress: string;
}

export class MessageSerializer<MessageSpecialization extends Message> {
  // Ideally, the members of this class would be part of `Message`, but TS
  // doesn't support static abstract members:
  // https://github.com/microsoft/TypeScript/issues/34516

  constructor(
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

  public async deserialize(serialization: ArrayBuffer): Promise<any> {
    const messageParts = parseMessage(serialization);

    this.validateMessageParts(messageParts);
  }

  private validateMessageParts(messageParts: MessageParts): void {
    //region Message type validation
    if (messageParts.concreteMessageType !== this.concreteMessageTypeOctet) {
      const expectedMessageTypeHex = decimalToHex(this.concreteMessageTypeOctet);
      const actualMessageTypeHex = decimalToHex(messageParts.concreteMessageType);
      throw new RAMFError(
        `Expected concrete message type ${expectedMessageTypeHex} but got ${actualMessageTypeHex}`
      );
    }
    //endregion

    //region Message version validation
    if (messageParts.concreteMessageVersion !== this.concreteMessageVersionOctet) {
      const expectedVersionHex = decimalToHex(this.concreteMessageVersionOctet);
      const actualVersionHex = decimalToHex(messageParts.concreteMessageVersion);
      throw new RAMFError(
        `Expected concrete message version ${expectedVersionHex} but got ${actualVersionHex}`
      );
    }
    //endregion

    field_validators.validateRecipientAddressLength(messageParts.recipientAddress);
  }
}

function parseMessage(serialization: ArrayBuffer): MessageParts {
  try {
    return PARSER.parse(Buffer.from(serialization));
  } catch (error) {
    throw new RAMFError(error, 'Serialization is not a valid RAMF message');
  }
}

function decimalToHex(numberDecimal: number): string {
  return '0x' + numberDecimal.toString(16);
}
