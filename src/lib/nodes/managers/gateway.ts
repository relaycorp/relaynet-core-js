import bufferToArray from 'buffer-to-arraybuffer';

import Certificate from '../../crypto_wrappers/x509/Certificate';
import Cargo from '../../messages/Cargo';
import { CargoCollectionRequest } from '../../messages/payloads/CargoCollectionRequest';
import CargoMessageSet, { MessageWithExpiryDate } from '../../messages/payloads/CargoMessageSet';
import { RAMF_MAX_TTL } from '../../ramf/serialization';
import { BaseNodeManager } from './BaseNodeManager';

const CLOCK_DRIFT_TOLERANCE_HOURS = 3;

export type CargoMessageStream = AsyncIterable<{
  readonly message: Buffer;
  readonly expiryDate: Date;
}>;

export class GatewayManager extends BaseNodeManager<CargoMessageSet | CargoCollectionRequest> {
  public async *generateCargoes(
    messages: CargoMessageStream,
    recipientPrivateAddress: string,
    privateKey: CryptoKey,
    senderCertificate: Certificate,
    recipientPublicAddress?: string,
  ): AsyncIterable<Buffer> {
    const messagesAsArrayBuffers = convertBufferMessagesToArrayBuffer(messages);
    const cargoMessageSets = CargoMessageSet.batchMessagesSerialized(messagesAsArrayBuffers);
    const recipientAddress = recipientPublicAddress ?? recipientPrivateAddress;
    for await (const { messageSerialized, expiryDate } of cargoMessageSets) {
      const creationDate = getCargoCreationTime();
      const ttl = getSecondsBetweenDates(creationDate, expiryDate);
      const cargo = new Cargo(
        recipientAddress,
        senderCertificate,
        await this.encryptPayload(messageSerialized, recipientPrivateAddress),
        { creationDate, ttl: Math.min(ttl, RAMF_MAX_TTL) },
      );
      const cargoSerialized = await cargo.serialize(privateKey, this.cryptoOptions.signature);
      yield Buffer.from(cargoSerialized);
    }
  }

  protected async encryptPayload(
    payloadPlaintext: ArrayBuffer,
    recipientPrivateAddress: string,
  ): Promise<Buffer> {
    const ciphertext = await this.wrapMessagePayload(payloadPlaintext, recipientPrivateAddress);
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
