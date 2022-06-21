import Parcel from '../../messages/Parcel';
import { RecipientAddressType } from '../../messages/RecipientAddressType';
export class ParcelCollection {
    parcelSerialized;
    trustedCertificates;
    ackCallback;
    constructor(parcelSerialized, trustedCertificates, ackCallback) {
        this.parcelSerialized = parcelSerialized;
        this.trustedCertificates = trustedCertificates;
        this.ackCallback = ackCallback;
    }
    async ack() {
        await this.ackCallback();
    }
    async deserializeAndValidateParcel() {
        const parcel = await Parcel.deserialize(this.parcelSerialized);
        await parcel.validate(RecipientAddressType.PRIVATE, this.trustedCertificates);
        return parcel;
    }
}
//# sourceMappingURL=ParcelCollection.js.map