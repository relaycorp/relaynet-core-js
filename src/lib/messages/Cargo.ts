// This module wouldn't duplicate Parcel.ts if TypeScript supported static+abstract members

import { SignatureOptions } from '../crypto_wrappers/cms/signedData';
import * as serialization from '../ramf/serialization';
import CargoMessageSet from './CargoMessageSet';
import Message from './Message';

const concreteMessageTypeOctet = 0x43;
const concreteMessageVersionOctet = 0;

export default class Cargo extends Message<CargoMessageSet> {
  public static async deserialize(parcelSerialized: ArrayBuffer): Promise<Cargo> {
    return serialization.deserialize(
      parcelSerialized,
      concreteMessageTypeOctet,
      concreteMessageVersionOctet,
      Cargo,
    );
  }

  protected readonly deserializePayload = CargoMessageSet.deserialize;

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
