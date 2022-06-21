import { SignatureOptions } from '../..';
import CargoMessageSet from './payloads/CargoMessageSet';
import RAMFMessage from './RAMFMessage';
export default class Cargo extends RAMFMessage<CargoMessageSet> {
    static deserialize(cargoSerialized: ArrayBuffer): Promise<Cargo>;
    protected readonly deserializePayload: typeof CargoMessageSet.deserialize;
    serialize(senderPrivateKey: CryptoKey, signatureOptions?: Partial<SignatureOptions>): Promise<ArrayBuffer>;
}
