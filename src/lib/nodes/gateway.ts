import bufferToArray from 'buffer-to-arraybuffer';

import { SessionlessEnvelopedData } from '../crypto_wrappers/cms/envelopedData';
import Certificate from '../crypto_wrappers/x509/Certificate';
import Cargo from '../messages/Cargo';
import { CargoCollectionRequest } from '../messages/payloads/CargoCollectionRequest';
import CargoMessageSet, { MessageWithExpiryDate } from '../messages/payloads/CargoMessageSet';
import { BaseNodeManager } from './BaseNodeManager';

const CLOCK_DRIFT_TOLERANCE_HOURS = 3;

export type CargoMessageStream = AsyncIterable<{
  readonly message: Buffer;
  readonly expiryDate: Date;
}>;

export class GatewayManager extends BaseNodeManager<CargoMessageSet | CargoCollectionRequest> {
  public async *generateCargoes(
    messages: CargoMessageStream,
    recipientCertificate: Certificate,
    privateKey: CryptoKey,
    certificate: Certificate,
    recipientPublicAddress?: string,
  ): AsyncIterable<Buffer> {
    const messagesAsArrayBuffers = convertBufferMessagesToArrayBuffer(messages);
    const cargoMessageSets = CargoMessageSet.batchMessagesSerialized(messagesAsArrayBuffers);
    const recipientAddress =
      recipientPublicAddress ?? (await recipientCertificate.calculateSubjectPrivateAddress());
    for await (const { messageSerialized, expiryDate } of cargoMessageSets) {
      const creationDate = getCargoCreationTime();
      const cargo = new Cargo(
        recipientAddress,
        certificate,
        await this.encryptPayload(messageSerialized, recipientCertificate),
        { creationDate, ttl: getSecondsBetweenDates(creationDate, expiryDate) },
      );
      const cargoSerialized = await cargo.serialize(privateKey, this.cryptoOptions.signature);
      yield Buffer.from(cargoSerialized);
    }
  }

  protected async encryptPayload(
    payloadPlaintext: ArrayBuffer,
    recipientCertificate: Certificate,
  ): Promise<Buffer> {
    const peerPrivateAddress = await recipientCertificate.calculateSubjectPrivateAddress();

    let ciphertext: ArrayBuffer;
    try {
      ciphertext = await this.wrapMessagePayload(payloadPlaintext, peerPrivateAddress);
    } catch (_) {
      const envelopedData = await SessionlessEnvelopedData.encrypt(
        payloadPlaintext,
        recipientCertificate,
        this.cryptoOptions.encryption,
      );
      ciphertext = envelopedData.serialize();
    }
    return Buffer.from(ciphertext);
  }
}

function getCargoCreationTime(): Date {
  const creationDate = new Date();
  creationDate.setMilliseconds(0);
  creationDate.setHours(creationDate.getHours() - CLOCK_DRIFT_TOLERANCE_HOURS);
  return creationDate;
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
