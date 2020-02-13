import { SignatureOptions } from '../crypto_wrappers/cms/signedData';
import * as serialization from '../ramf/serialization';
import Message from './Message';

const concreteMessageTypeOctet = 0x50;
const concreteMessageVersionOctet = 0;

export default class Parcel extends Message {
  public static async deserialize(parcelSerialized: ArrayBuffer): Promise<Parcel> {
    return serialization.deserialize(
      parcelSerialized,
      concreteMessageTypeOctet,
      concreteMessageVersionOctet,
      Parcel,
    );
  }

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
