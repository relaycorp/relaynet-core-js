export declare class ParcelDelivery {
    deliveryId: string;
    parcelSerialized: ArrayBuffer;
    static deserialize(serialization: ArrayBuffer): ParcelDelivery;
    private static readonly SCHEMA;
    constructor(deliveryId: string, parcelSerialized: ArrayBuffer);
    serialize(): ArrayBuffer;
}
