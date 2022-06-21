import { SignatureOptions } from '../..';
import { CargoCollectionRequest } from './payloads/CargoCollectionRequest';
import RAMFMessage from './RAMFMessage';
export declare class CargoCollectionAuthorization extends RAMFMessage<CargoCollectionRequest> {
    static deserialize(cargoSerialized: ArrayBuffer): Promise<CargoCollectionAuthorization>;
    protected readonly deserializePayload: typeof CargoCollectionRequest.deserialize;
    serialize(senderPrivateKey: CryptoKey, signatureOptions?: SignatureOptions): Promise<ArrayBuffer>;
}
