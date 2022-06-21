// This module wouldn't duplicate Parcel.ts if TypeScript supported static+abstract members
import * as serialization from '../ramf/serialization';
import { CargoCollectionRequest } from './payloads/CargoCollectionRequest';
import RAMFMessage from './RAMFMessage';
const concreteMessageTypeOctet = 0x44;
const concreteMessageVersionOctet = 0;
export class CargoCollectionAuthorization extends RAMFMessage {
    static async deserialize(cargoSerialized) {
        return serialization.deserialize(cargoSerialized, concreteMessageTypeOctet, concreteMessageVersionOctet, CargoCollectionAuthorization);
    }
    deserializePayload = CargoCollectionRequest.deserialize;
    async serialize(senderPrivateKey, signatureOptions) {
        return serialization.serialize(this, concreteMessageTypeOctet, concreteMessageVersionOctet, senderPrivateKey, signatureOptions);
    }
}
//# sourceMappingURL=CargoCollectionAuthorization.js.map