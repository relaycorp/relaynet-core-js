export declare class HandshakeChallenge {
    nonce: ArrayBuffer;
    static deserialize(serialization: ArrayBuffer): HandshakeChallenge;
    private static readonly SCHEMA;
    constructor(nonce: ArrayBuffer);
    serialize(): ArrayBuffer;
}
