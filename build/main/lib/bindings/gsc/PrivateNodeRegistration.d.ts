import Certificate from '../../crypto_wrappers/x509/Certificate';
import { SessionKey } from '../../SessionKey';
export declare class PrivateNodeRegistration {
    readonly privateNodeCertificate: Certificate;
    readonly gatewayCertificate: Certificate;
    readonly sessionKey: SessionKey | null;
    static deserialize(serialization: ArrayBuffer): Promise<PrivateNodeRegistration>;
    private static readonly SCHEMA;
    constructor(privateNodeCertificate: Certificate, gatewayCertificate: Certificate, sessionKey?: SessionKey | null);
    serialize(): Promise<ArrayBuffer>;
}
