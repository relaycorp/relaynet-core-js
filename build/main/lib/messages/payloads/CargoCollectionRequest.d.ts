import Certificate from '../../crypto_wrappers/x509/Certificate';
import PayloadPlaintext from './PayloadPlaintext';
export declare class CargoCollectionRequest implements PayloadPlaintext {
    readonly cargoDeliveryAuthorization: Certificate;
    static deserialize(serialization: ArrayBuffer): CargoCollectionRequest;
    private static readonly SCHEMA;
    constructor(cargoDeliveryAuthorization: Certificate);
    serialize(): ArrayBuffer;
}
