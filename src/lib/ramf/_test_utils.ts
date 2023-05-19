/* tslint:disable:max-classes-per-file */

import { SignatureOptions } from '../..';
import { PayloadPlaintext } from '../messages/payloads/PayloadPlaintext';
import { RAMFMessage } from '../messages/RAMFMessage';
import * as serialization from './serialization';

export class StubPayload implements PayloadPlaintext {
  constructor(public readonly content: ArrayBuffer) {}

  public serialize(): ArrayBuffer {
    return this.content;
  }
}

export class StubMessage extends RAMFMessage<StubPayload> {
  protected static readonly concreteMessageTypeOctet = 0xff;
  protected static readonly concreteMessageVersionOctet = 0xf0;

  public static async deserialize(messageSerialized: ArrayBuffer): Promise<StubMessage> {
    return serialization.deserialize(
      messageSerialized,
      StubMessage.concreteMessageTypeOctet,
      StubMessage.concreteMessageVersionOctet,
      StubMessage,
    );
  }

  public async serialize(
    senderPrivateKey: CryptoKey,
    signatureOptions?: SignatureOptions,
  ): Promise<ArrayBuffer> {
    return serialization.serialize(
      this,
      StubMessage.concreteMessageTypeOctet,
      StubMessage.concreteMessageVersionOctet,
      senderPrivateKey,
      signatureOptions,
    );
  }

  protected deserializePayload(payloadPlaintext: ArrayBuffer): StubPayload {
    return new StubPayload(payloadPlaintext);
  }
}
