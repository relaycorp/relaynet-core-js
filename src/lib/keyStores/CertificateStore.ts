import { CertificationPath } from '../pki/CertificationPath';

/**
 * Store of certificates.
 */
export abstract class CertificateStore {
  /**
   * Store `subjectCertificate` as long as it's still valid.
   *
   * @param path
   * @param issuerId
   *
   * Whilst we could take the {issuerId} from the leaf certificate in the {path}, we
   * must not rely on it because we don't have enough information/context here to be certain that
   * the value is legitimate. Additionally, the value has to be present in an X.509 extension,
   * which could be absent if produced by a non-compliant implementation.
   */
  public async save(path: CertificationPath, issuerId: string): Promise<void> {
    if (new Date() < path.leafCertificate.expiryDate) {
      await this.saveData(
        path.serialize(),
        await path.leafCertificate.calculateSubjectId(),
        path.leafCertificate.expiryDate,
        issuerId,
      );
    }
  }

  public async retrieveLatest(
    subjectId: string,
    issuerId: string,
  ): Promise<CertificationPath | null> {
    const serialization = await this.retrieveLatestSerialization(subjectId, issuerId);
    if (!serialization) {
      return null;
    }
    const path = CertificationPath.deserialize(serialization);
    return new Date() < path.leafCertificate.expiryDate ? path : null;
  }

  public async retrieveAll(
    subjectId: string,
    issuerId: string,
  ): Promise<readonly CertificationPath[]> {
    const allSerializations = await this.retrieveAllSerializations(subjectId, issuerId);
    return allSerializations
      .map(CertificationPath.deserialize)
      .filter((p) => new Date() < p.leafCertificate.expiryDate);
  }

  public abstract deleteExpired(): Promise<void>;

  protected abstract saveData(
    serialization: ArrayBuffer,
    subjectId: string,
    subjectCertificateExpiryDate: Date,
    issuerId: string,
  ): Promise<void>;

  protected abstract retrieveLatestSerialization(
    subjectId: string,
    issuerId: string,
  ): Promise<ArrayBuffer | null>;

  protected abstract retrieveAllSerializations(
    subjectId: string,
    issuerId: string,
  ): Promise<readonly ArrayBuffer[]>;
}
