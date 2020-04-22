import bufferToArray from 'buffer-to-arraybuffer';

import {
  EnvelopedData,
  OriginatorSessionKey,
  SessionEnvelopedData,
  SessionlessEnvelopedData,
} from '../crypto_wrappers/cms/envelopedData';
import Certificate from '../crypto_wrappers/x509/Certificate';
import Cargo from '../messages/Cargo';
import CargoMessageSet, { MessageWithExpiryDate } from '../messages/payloads/CargoMessageSet';
import { BaseNode } from './baseNode';

export type CargoMessageStream = AsyncIterable<{
  readonly message: Buffer;
  readonly expiryDate: Date;
}>;

export class Gateway extends BaseNode {
  public async *generateCargoes(
    messages: CargoMessageStream,
    recipientCertificate: Certificate,
    currentKeyId: Buffer,
  ): AsyncIterable<Buffer> {
    const { privateKey, certificate } = await this.privateKeyStore.fetchNodeKey(currentKeyId);

    const messagesAsArrayBuffers = convertBufferMessagesToArrayBuffer(messages);
    const cargoMessageSets = CargoMessageSet.batchMessagesSerialized(messagesAsArrayBuffers);
    for await (const { messageSerialized, expiryDate } of cargoMessageSets) {
      const cargoPayload = await this.encryptPayload(messageSerialized, recipientCertificate);
      const creationDate = new Date();
      creationDate.setMilliseconds(0);
      const ttl = Math.floor((expiryDate.getTime() - creationDate.getTime()) / 1_000);
      const cargo = new Cargo('the-address', certificate, cargoPayload, {
        date: creationDate,
        ttl,
      });
      yield Buffer.from(await cargo.serialize(privateKey, this.cryptoOptions.signature));
    }
  }

  // TODO: Move to base class
  protected async encryptPayload(
    payloadPlaintext: ArrayBuffer,
    recipientCertificate: Certificate,
  ): Promise<Buffer> {
    // tslint:disable-next-line:no-let
    let sessionKey: OriginatorSessionKey | undefined;
    try {
      sessionKey = await this.publicKeyStore.fetchLastSessionKey(recipientCertificate);
    } catch (_) {
      sessionKey = undefined;
    }

    // tslint:disable-next-line:no-let
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
}

async function* convertBufferMessagesToArrayBuffer(
  messages: CargoMessageStream,
): AsyncGenerator<MessageWithExpiryDate> {
  for await (const { message, expiryDate } of messages) {
    yield { expiryDate, messageSerialized: bufferToArray(message) };
  }
}
