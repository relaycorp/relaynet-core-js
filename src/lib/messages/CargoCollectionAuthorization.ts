// This module wouldn't duplicate Parcel.ts if TypeScript supported static+abstract members

import { SignatureOptions } from '../..';
import * as serialization from '../ramf/serialization';
import EmptyPayloadPlaintext from './payloads/EmptyPayloadPlaintext';
import RAMFMessage from './RAMFMessage';

const concreteMessageTypeOctet = 0x44;
const concreteMessageVersionOctet = 0;

export class CargoCollectionAuthorization extends RAMFMessage<EmptyPayloadPlaintext> {
  public static async deserialize(
    cargoSerialized: ArrayBuffer,
  ): Promise<CargoCollectionAuthorization> {
    return serialization.deserialize(
      cargoSerialized,
      concreteMessageTypeOctet,
      concreteMessageVersionOctet,
      CargoCollectionAuthorization,
    );
  }

  protected readonly deserializePayload = EmptyPayloadPlaintext.deserialize;

  public async serialize(
    senderPrivateKey: CryptoKey,
    signatureOptions?: SignatureOptions,
  ): Promise<ArrayBuffer> {
    return serialization.serialize(
      this,
      concreteMessageTypeOctet,
      concreteMessageVersionOctet,
      senderPrivateKey,
      signatureOptions,
    );
  }
}
