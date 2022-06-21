"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertificateStore = void 0;
const CertificationPath_1 = require("../pki/CertificationPath");
/**
 * Store of certificates.
 */
class CertificateStore {
    /**
     * Store `subjectCertificate` as long as it's still valid.
     *
     * @param path
     * @param issuerPrivateAddress
     *
     * Whilst we could take the {issuerPrivateAddress} from the leaf certificate in the {path}, we
     * must not rely on it because we don't have enough information/context here to be certain that
     * the value is legitimate. Additionally, the value has to be present in an X.509 extension,
     * which could be absent if produced by a non-compliant implementation.
     */
    async save(path, issuerPrivateAddress) {
        if (new Date() < path.leafCertificate.expiryDate) {
            await this.saveData(path.serialize(), await path.leafCertificate.calculateSubjectPrivateAddress(), path.leafCertificate.expiryDate, issuerPrivateAddress);
        }
    }
    async retrieveLatest(subjectPrivateAddress, issuerPrivateAddress) {
        const serialization = await this.retrieveLatestSerialization(subjectPrivateAddress, issuerPrivateAddress);
        if (!serialization) {
            return null;
        }
        const path = CertificationPath_1.CertificationPath.deserialize(serialization);
        return new Date() < path.leafCertificate.expiryDate ? path : null;
    }
    async retrieveAll(subjectPrivateAddress, issuerPrivateAddress) {
        const allSerializations = await this.retrieveAllSerializations(subjectPrivateAddress, issuerPrivateAddress);
        return allSerializations
            .map(CertificationPath_1.CertificationPath.deserialize)
            .filter((p) => new Date() < p.leafCertificate.expiryDate);
    }
}
exports.CertificateStore = CertificateStore;
//# sourceMappingURL=CertificateStore.js.map