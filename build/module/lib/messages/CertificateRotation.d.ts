import { CertificationPath } from '../pki/CertificationPath';
export declare const CERTIFICATE_ROTATION_FORMAT_SIGNATURE: Uint8Array;
export declare class CertificateRotation {
    readonly certificationPath: CertificationPath;
    static deserialize(serialization: ArrayBuffer): CertificateRotation;
    constructor(certificationPath: CertificationPath);
    serialize(): ArrayBuffer;
}
