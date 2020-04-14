// This module wouldn't duplicate Parcel.ts if TypeScript supported static+abstract members

import { SignatureOptions } from '../crypto_wrappers/cms/signedData';
import * as serialization from '../ramf/serialization';
import Message from './Message';
import EmptyPayloadPlaintext from './payloads/EmptyPayloadPlaintext';

const concreteMessageTypeOctet = 0x44;
const concreteMessageVersionOctet = 0;

export class CargoCollectionAuthorization extends Message<EmptyPayloadPlaintext> {
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
