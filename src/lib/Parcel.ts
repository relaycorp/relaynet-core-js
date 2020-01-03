import { SignatureOptions } from './crypto_wrappers/cms/signedData';
import Message from './ramf/Message';
import * as serialization from './ramf/serialization';

const concreteMessageTypeOctet = 0x50;
const concreteMessageVersionOctet = 0;

export default class Parcel extends Message {
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
