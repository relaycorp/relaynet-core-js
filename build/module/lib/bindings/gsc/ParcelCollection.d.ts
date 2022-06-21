import Certificate from '../../crypto_wrappers/x509/Certificate';
import Parcel from '../../messages/Parcel';
export declare class ParcelCollection {
    readonly parcelSerialized: ArrayBuffer;
    readonly trustedCertificates: readonly Certificate[];
    private readonly ackCallback;
    constructor(parcelSerialized: ArrayBuffer, trustedCertificates: readonly Certificate[], ackCallback: () => Promise<void>);
    ack(): Promise<void>;
    deserializeAndValidateParcel(): Promise<Parcel>;
}
