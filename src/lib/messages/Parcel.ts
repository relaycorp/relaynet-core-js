// This module wouldn't duplicate Cargo.ts if TypeScript supported static+abstract members

import { SignatureOptions } from '../crypto_wrappers/cms/signedData';
import * as serialization from '../ramf/serialization';
import Message from './Message';
import ServiceMessage from './payloads/ServiceMessage';

const concreteMessageTypeOctet = 0x50;
const concreteMessageVersionOctet = 0;

export default class Parcel extends Message<ServiceMessage> {
  public static async deserialize(parcelSerialized: ArrayBuffer): Promise<Parcel> {
    return serialization.deserialize(
      parcelSerialized,
      concreteMessageTypeOctet,
      concreteMessageVersionOctet,
      Parcel,
    );
  }

  protected readonly deserializePayload = ServiceMessage.deserialize;

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
