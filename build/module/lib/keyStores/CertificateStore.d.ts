import { CertificationPath } from '../pki/CertificationPath';
/**
 * Store of certificates.
 */
export declare abstract class CertificateStore {
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
    save(path: CertificationPath, issuerPrivateAddress: string): Promise<void>;
    retrieveLatest(subjectPrivateAddress: string, issuerPrivateAddress: string): Promise<CertificationPath | null>;
    retrieveAll(subjectPrivateAddress: string, issuerPrivateAddress: string): Promise<readonly CertificationPath[]>;
    abstract deleteExpired(): Promise<void>;
    protected abstract saveData(serialization: ArrayBuffer, subjectPrivateAddress: string, subjectCertificateExpiryDate: Date, issuerPrivateAddress: string): Promise<void>;
    protected abstract retrieveLatestSerialization(subjectPrivateAddress: string, issuerPrivateAddress: string): Promise<ArrayBuffer | null>;
    protected abstract retrieveAllSerializations(subjectPrivateAddress: string, issuerPrivateAddress: string): Promise<readonly ArrayBuffer[]>;
}
