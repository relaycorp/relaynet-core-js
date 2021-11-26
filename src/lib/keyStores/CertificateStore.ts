import Certificate from '../crypto_wrappers/x509/Certificate';

/**
 * Store of certificates.
 */
export abstract class CertificateStore {
  /**
   * Store `certificate` as long as it's still valid.
   *
   * @param certificate
   */
  public async save(certificate: Certificate): Promise<void> {
    if (new Date() < certificate.expiryDate) {
      await this.saveData(
        await certificate.calculateSubjectPrivateAddress(),
        certificate.serialize(),
        certificate.expiryDate,
      );
    }
  }

  public async retrieveLatest(subjectPrivateAddress: string): Promise<Certificate | null> {
    const serialization = await this.retrieveLatestSerialization(subjectPrivateAddress);
    if (!serialization) {
      return null;
    }
    const certificate = Certificate.deserialize(serialization);
    return new Date() < certificate.expiryDate ? certificate : null;
  }

  public async retrieveAll(subjectPrivateAddress: string): Promise<readonly Certificate[]> {
    const allCertificatesSerialized = await this.retrieveAllSerializations(subjectPrivateAddress);
    return allCertificatesSerialized
      .map((s) => Certificate.deserialize(s))
      .filter((c) => new Date() < c.expiryDate);
  }

  public abstract deleteExpired(): Promise<void>;

  protected abstract saveData(
    subjectPrivateAddress: string,
    subjectCertificateSerialized: ArrayBuffer,
    subjectCertificateExpiryDate: Date,
  ): Promise<void>;

  protected abstract retrieveLatestSerialization(
    subjectPrivateAddress: string,
  ): Promise<ArrayBuffer | null>;

  protected abstract retrieveAllSerializations(
    subjectPrivateAddress: string,
  ): Promise<readonly ArrayBuffer[]>;
}
