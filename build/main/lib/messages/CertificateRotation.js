"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertificateRotation = exports.CERTIFICATE_ROTATION_FORMAT_SIGNATURE = void 0;
const CertificationPath_1 = require("../pki/CertificationPath");
const formatSignature_1 = require("./formatSignature");
const InvalidMessageError_1 = __importDefault(require("./InvalidMessageError"));
exports.CERTIFICATE_ROTATION_FORMAT_SIGNATURE = (0, formatSignature_1.generateFormatSignature)(0x10, 0);
class CertificateRotation {
    constructor(certificationPath) {
        this.certificationPath = certificationPath;
    }
    static deserialize(serialization) {
        const formatSignature = Buffer.from(serialization.slice(0, exports.CERTIFICATE_ROTATION_FORMAT_SIGNATURE.byteLength));
        if (!formatSignature.equals(exports.CERTIFICATE_ROTATION_FORMAT_SIGNATURE)) {
            throw new InvalidMessageError_1.default('Format signature should be that of a CertificateRotation');
        }
        const certificationPathSerialized = serialization.slice(formatSignature.byteLength);
        let certificationPath;
        try {
            certificationPath = CertificationPath_1.CertificationPath.deserialize(certificationPathSerialized);
        }
        catch (err) {
            throw new InvalidMessageError_1.default(err, 'CertificationPath is malformed');
        }
        return new CertificateRotation(certificationPath);
    }
    serialize() {
        const pathSerialized = this.certificationPath.serialize();
        const serialization = new ArrayBuffer(exports.CERTIFICATE_ROTATION_FORMAT_SIGNATURE.byteLength + pathSerialized.byteLength);
        const serializationView = new Uint8Array(serialization);
        serializationView.set(exports.CERTIFICATE_ROTATION_FORMAT_SIGNATURE, 0);
        serializationView.set(new Uint8Array(pathSerialized), exports.CERTIFICATE_ROTATION_FORMAT_SIGNATURE.byteLength);
        return serialization;
    }
}
exports.CertificateRotation = CertificateRotation;
//# sourceMappingURL=CertificateRotation.js.map