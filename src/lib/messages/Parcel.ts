// This module wouldn't duplicate Cargo.ts if TypeScript supported static+abstract members

import { SignatureOptions } from '../crypto_wrappers/cms/signedData';
import * as serialization from '../ramf/serialization';
import InvalidMessageError from './InvalidMessageError';
import Message from './Message';
import CargoMessageSet from './payloads/CargoMessageSet';
import ServiceMessage from './payloads/ServiceMessage';

const concreteMessageTypeOctet = 0x50;
const concreteMessageVersionOctet = 0;

export default class Parcel extends Message<ServiceMessage> {
  public static async deserialize(parcelSerialized: ArrayBuffer): Promise<Parcel> {
    if (CargoMessageSet.MAX_MESSAGE_LENGTH < parcelSerialized.byteLength) {
      throw new InvalidMessageError(
        `Parcels must not span more than ${CargoMessageSet.MAX_MESSAGE_LENGTH} octets ` +
          `(got ${parcelSerialized.byteLength} octets)`,
      );
    }
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
