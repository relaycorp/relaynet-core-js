// This module wouldn't duplicate Parcel.ts if TypeScript supported static+abstract members

import { SignatureOptions } from '../crypto_wrappers/cms/signedData';
import * as serialization from '../ramf/serialization';
import Message from './Message';
import CargoMessageSet from './payloads/CargoMessageSet';

const concreteMessageTypeOctet = 0x43;
const concreteMessageVersionOctet = 0;

export default class Cargo extends Message<CargoMessageSet> {
  public static async deserialize(cargoSerialized: ArrayBuffer): Promise<Cargo> {
    return serialization.deserialize(
      cargoSerialized,
      concreteMessageTypeOctet,
      concreteMessageVersionOctet,
      Cargo,
    );
  }

  protected readonly deserializePayload = CargoMessageSet.deserialize;

  public async serialize(
    senderPrivateKey: CryptoKey,
    signatureOptions?: Partial<SignatureOptions>,
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
