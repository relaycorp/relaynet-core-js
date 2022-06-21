import { SessionKey } from '../SessionKey';
export declare class PublicNodeConnectionParams {
    readonly publicAddress: string;
    readonly identityKey: CryptoKey;
    readonly sessionKey: SessionKey;
    static deserialize(serialization: ArrayBuffer): Promise<PublicNodeConnectionParams>;
    private static readonly SCHEMA;
    constructor(publicAddress: string, identityKey: CryptoKey, sessionKey: SessionKey);
    serialize(): Promise<ArrayBuffer>;
}
