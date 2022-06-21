export declare class PrivateNodeRegistrationAuthorization {
    readonly expiryDate: Date;
    readonly gatewayData: ArrayBuffer;
    static deserialize(serialization: ArrayBuffer, gatewayPublicKey: CryptoKey): Promise<PrivateNodeRegistrationAuthorization>;
    private static readonly SCHEMA;
    private static makeSignaturePlaintext;
    constructor(expiryDate: Date, gatewayData: ArrayBuffer);
    serialize(gatewayPrivateKey: CryptoKey): Promise<ArrayBuffer>;
}
