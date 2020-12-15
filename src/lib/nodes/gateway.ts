import bufferToArray from 'buffer-to-arraybuffer';

import {
  EnvelopedData,
  OriginatorSessionKey,
  SessionEnvelopedData,
  SessionlessEnvelopedData,
} from '../crypto_wrappers/cms/envelopedData';
import Certificate from '../crypto_wrappers/x509/Certificate';
import Cargo from '../messages/Cargo';
import { CargoCollectionRequest } from '../messages/payloads/CargoCollectionRequest';
import CargoMessageSet, { MessageWithExpiryDate } from '../messages/payloads/CargoMessageSet';
import { BaseNode } from './BaseNode';

export type CargoMessageStream = AsyncIterable<{
  readonly message: Buffer;
  readonly expiryDate: Date;
}>;

export class Gateway extends BaseNode<CargoMessageSet | CargoCollectionRequest> {
  public async *generateCargoes(
    messages: CargoMessageStream,
    recipientCertificate: Certificate,
    privateKey: CryptoKey,
    certificate: Certificate,
  ): AsyncIterable<Buffer> {
    const messagesAsArrayBuffers = convertBufferMessagesToArrayBuffer(messages);
    const cargoMessageSets = CargoMessageSet.batchMessagesSerialized(messagesAsArrayBuffers);
    for await (const { messageSerialized, expiryDate } of cargoMessageSets) {
      const creationDate = new Date();
      creationDate.setMilliseconds(0);
      const cargo = new Cargo(
        await recipientCertificate.calculateSubjectPrivateAddress(),
        certificate,
        await this.encryptPayload(messageSerialized, recipientCertificate),
        { creationDate, ttl: getSecondsBetweenDates(creationDate, expiryDate) },
      );
      const cargoSerialized = await cargo.serialize(privateKey, this.cryptoOptions.signature);
      yield Buffer.from(cargoSerialized);
    }
  }

  // TODO: Move to base class
  protected async encryptPayload(
    payloadPlaintext: ArrayBuffer,
    recipientCertificate: Certificate,
  ): Promise<Buffer> {
    const sessionKey = await this.fetchSessionKeyForRecipient(recipientCertificate);

    let envelopedData: EnvelopedData;
    if (sessionKey) {
      const encryptionResult = await SessionEnvelopedData.encrypt(
        payloadPlaintext,
        sessionKey,
        this.cryptoOptions.encryption,
      );
      await this.privateKeyStore.saveSubsequentSessionKey(
        encryptionResult.dhPrivateKey,
        Buffer.from(encryptionResult.dhKeyId),
        recipientCertificate,
      );
      envelopedData = encryptionResult.envelopedData;
    } else {
      envelopedData = await SessionlessEnvelopedData.encrypt(
        payloadPlaintext,
        recipientCertificate,
        this.cryptoOptions.encryption,
      );
    }
    return Buffer.from(envelopedData.serialize());
  }

  private async fetchSessionKeyForRecipient(
    recipientCertificate: Certificate,
  ): Promise<OriginatorSessionKey | undefined> {
    try {
      return await this.publicKeyStore.fetchLastSessionKey(recipientCertificate);
    } catch (_) {
      return undefined;
    }
  }
}

async function* convertBufferMessagesToArrayBuffer(
  messages: CargoMessageStream,
): AsyncGenerator<MessageWithExpiryDate> {
  for await (const { message, expiryDate } of messages) {
    yield { expiryDate, messageSerialized: bufferToArray(message) };
  }
}

function getSecondsBetweenDates(date: Date, expiryDate: Date): number {
  return Math.floor((expiryDate.getTime() - date.getTime()) / 1_000);
}
