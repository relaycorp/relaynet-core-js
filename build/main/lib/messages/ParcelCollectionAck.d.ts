export declare class ParcelCollectionAck {
    readonly senderEndpointPrivateAddress: string;
    readonly recipientEndpointAddress: string;
    readonly parcelId: string;
    static readonly FORMAT_SIGNATURE: Uint8Array;
    static deserialize(pcaSerialized: ArrayBuffer): ParcelCollectionAck;
    private static readonly SCHEMA;
    constructor(senderEndpointPrivateAddress: string, recipientEndpointAddress: string, parcelId: string);
    serialize(): ArrayBuffer;
}
