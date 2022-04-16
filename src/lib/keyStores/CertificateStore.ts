import { CertificationPath } from '../pki/CertificationPath';

/**
 * Store of certificates.
 */
export abstract class CertificateStore {
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
  public async save(path: CertificationPath, issuerPrivateAddress: string): Promise<void> {
    if (new Date() < path.leafCertificate.expiryDate) {
      await this.saveData(
        path.serialize(),
        await path.leafCertificate.calculateSubjectPrivateAddress(),
        path.leafCertificate.expiryDate,
        issuerPrivateAddress,
      );
    }
  }

  public async retrieveLatest(
    subjectPrivateAddress: string,
    issuerPrivateAddress: string,
  ): Promise<CertificationPath | null> {
    const serialization = await this.retrieveLatestSerialization(
      subjectPrivateAddress,
      issuerPrivateAddress,
    );
    if (!serialization) {
      return null;
    }
    const path = CertificationPath.deserialize(serialization);
    return new Date() < path.leafCertificate.expiryDate ? path : null;
  }

  public async retrieveAll(
    subjectPrivateAddress: string,
    issuerPrivateAddress: string,
  ): Promise<readonly CertificationPath[]> {
    const allSerializations = await this.retrieveAllSerializations(
      subjectPrivateAddress,
      issuerPrivateAddress,
    );
    return allSerializations
      .map(CertificationPath.deserialize)
      .filter((p) => new Date() < p.leafCertificate.expiryDate);
  }

  public abstract deleteExpired(): Promise<void>;

  protected abstract saveData(
    serialization: ArrayBuffer,
    subjectPrivateAddress: string,
    subjectCertificateExpiryDate: Date,
    issuerPrivateAddress: string,
  ): Promise<void>;

  protected abstract retrieveLatestSerialization(
    subjectPrivateAddress: string,
    issuerPrivateAddress: string,
  ): Promise<ArrayBuffer | null>;

  protected abstract retrieveAllSerializations(
    subjectPrivateAddress: string,
    issuerPrivateAddress: string,
  ): Promise<readonly ArrayBuffer[]>;
}
