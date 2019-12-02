import bufferToArray from 'buffer-to-arraybuffer';
import { SmartBuffer } from 'smart-buffer';

import { encrypt, EncryptionOptions, sign, SignatureOptions } from '../cms';
import Certificate from '../pki/Certificate';
import Message from './Message';
import Payload from './Payload';
import RAMFError from './RAMFError';

const MAX_SIGNATURE_LENGTH = 2 ** 14 - 1;

export class MessageSerializer<MessageSpecialization extends Message<Payload>> {
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
      message.payload.serialize(),
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
}
