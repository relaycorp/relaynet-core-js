export declare class HandshakeResponse {
    nonceSignatures: readonly ArrayBuffer[];
    static deserialize(serialization: ArrayBuffer): HandshakeResponse;
    private static readonly SCHEMA;
    constructor(nonceSignatures: readonly ArrayBuffer[]);
    serialize(): ArrayBuffer;
}
