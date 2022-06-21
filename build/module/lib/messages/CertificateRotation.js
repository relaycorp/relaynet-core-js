import { CertificationPath } from '../pki/CertificationPath';
import { generateFormatSignature } from './formatSignature';
import InvalidMessageError from './InvalidMessageError';
export const CERTIFICATE_ROTATION_FORMAT_SIGNATURE = generateFormatSignature(0x10, 0);
export class CertificateRotation {
    certificationPath;
    static deserialize(serialization) {
        const formatSignature = Buffer.from(serialization.slice(0, CERTIFICATE_ROTATION_FORMAT_SIGNATURE.byteLength));
        if (!formatSignature.equals(CERTIFICATE_ROTATION_FORMAT_SIGNATURE)) {
            throw new InvalidMessageError('Format signature should be that of a CertificateRotation');
        }
        const certificationPathSerialized = serialization.slice(formatSignature.byteLength);
        let certificationPath;
        try {
            certificationPath = CertificationPath.deserialize(certificationPathSerialized);
        }
        catch (err) {
            throw new InvalidMessageError(err, 'CertificationPath is malformed');
        }
        return new CertificateRotation(certificationPath);
    }
    constructor(certificationPath) {
        this.certificationPath = certificationPath;
    }
    serialize() {
        const pathSerialized = this.certificationPath.serialize();
        const serialization = new ArrayBuffer(CERTIFICATE_ROTATION_FORMAT_SIGNATURE.byteLength + pathSerialized.byteLength);
        const serializationView = new Uint8Array(serialization);
        serializationView.set(CERTIFICATE_ROTATION_FORMAT_SIGNATURE, 0);
        serializationView.set(new Uint8Array(pathSerialized), CERTIFICATE_ROTATION_FORMAT_SIGNATURE.byteLength);
        return serialization;
    }
}
//# sourceMappingURL=CertificateRotation.js.map