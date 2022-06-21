// This module wouldn't duplicate Parcel.ts if TypeScript supported static+abstract members
import * as serialization from '../ramf/serialization';
import CargoMessageSet from './payloads/CargoMessageSet';
import RAMFMessage from './RAMFMessage';
const concreteMessageTypeOctet = 0x43;
const concreteMessageVersionOctet = 0;
export default class Cargo extends RAMFMessage {
    static async deserialize(cargoSerialized) {
        return serialization.deserialize(cargoSerialized, concreteMessageTypeOctet, concreteMessageVersionOctet, Cargo);
    }
    deserializePayload = CargoMessageSet.deserialize;
    async serialize(senderPrivateKey, signatureOptions) {
        return serialization.serialize(this, concreteMessageTypeOctet, concreteMessageVersionOctet, senderPrivateKey, signatureOptions);
    }
}
//# sourceMappingURL=Cargo.js.map