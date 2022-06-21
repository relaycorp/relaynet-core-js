export declare class PrivateNodeRegistrationRequest {
    readonly privateNodePublicKey: CryptoKey;
    readonly pnraSerialized: ArrayBuffer;
    static deserialize(serialization: ArrayBuffer): Promise<PrivateNodeRegistrationRequest>;
    private static readonly SCHEMA;
    private static makePNRACountersignaturePlaintext;
    constructor(privateNodePublicKey: CryptoKey, pnraSerialized: ArrayBuffer);
    serialize(privateNodePrivateKey: CryptoKey): Promise<ArrayBuffer>;
}
