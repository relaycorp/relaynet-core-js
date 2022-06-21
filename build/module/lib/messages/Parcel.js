// This module wouldn't duplicate Cargo.ts if TypeScript supported static+abstract members
import * as serialization from '../ramf/serialization';
import InvalidMessageError from './InvalidMessageError';
import CargoMessageSet from './payloads/CargoMessageSet';
import ServiceMessage from './payloads/ServiceMessage';
import RAMFMessage from './RAMFMessage';
const concreteMessageTypeOctet = 0x50;
const concreteMessageVersionOctet = 0;
export default class Parcel extends RAMFMessage {
    static async deserialize(parcelSerialized) {
        if (CargoMessageSet.MAX_MESSAGE_LENGTH < parcelSerialized.byteLength) {
            throw new InvalidMessageError(`Parcels must not span more than ${CargoMessageSet.MAX_MESSAGE_LENGTH} octets ` +
                `(got ${parcelSerialized.byteLength} octets)`);
        }
        return serialization.deserialize(parcelSerialized, concreteMessageTypeOctet, concreteMessageVersionOctet, Parcel);
    }
    deserializePayload = ServiceMessage.deserialize;
    async serialize(senderPrivateKey, signatureOptions) {
        return serialization.serialize(this, concreteMessageTypeOctet, concreteMessageVersionOctet, senderPrivateKey, signatureOptions);
    }
}
//# sourceMappingURL=Parcel.js.map