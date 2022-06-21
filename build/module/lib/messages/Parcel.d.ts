import { SignatureOptions } from '../..';
import ServiceMessage from './payloads/ServiceMessage';
import RAMFMessage from './RAMFMessage';
export default class Parcel extends RAMFMessage<ServiceMessage> {
    static deserialize(parcelSerialized: ArrayBuffer): Promise<Parcel>;
    protected readonly deserializePayload: typeof ServiceMessage.deserialize;
    serialize(senderPrivateKey: CryptoKey, signatureOptions?: SignatureOptions): Promise<ArrayBuffer>;
}
