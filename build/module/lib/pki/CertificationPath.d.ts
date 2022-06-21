import Certificate from '../crypto_wrappers/x509/Certificate';
export declare class CertificationPath {
    readonly leafCertificate: Certificate;
    readonly certificateAuthorities: readonly Certificate[];
    static deserialize(serialization: ArrayBuffer): CertificationPath;
    private static readonly SCHEMA;
    constructor(leafCertificate: Certificate, certificateAuthorities: readonly Certificate[]);
    serialize(): ArrayBuffer;
}
