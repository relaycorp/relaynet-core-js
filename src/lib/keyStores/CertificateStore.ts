import Certificate from '../crypto_wrappers/x509/Certificate';

/**
 * Store of certificates.
 */
export abstract class CertificateStore {
  /**
   * Store `certificate` as long as it's still valid.
   *
   * @param certificate
   * @param issuerPrivateAddress
   *
   * Whilst we could take the [issuerPrivateAddress] from the [certificate], we must not rely on
   * it because we don't have enough information/context here to be certain that the value is
   * legitimate. Additionally, the value has to be present in an X.509 extension, which could
   * be absent if produced by a non-compliant implementation.
   */
  public async save(certificate: Certificate, issuerPrivateAddress: string): Promise<void> {
    if (new Date() < certificate.expiryDate) {
      await this.saveData(
        await certificate.calculateSubjectPrivateAddress(),
        certificate.serialize(),
        certificate.expiryDate,
        issuerPrivateAddress,
      );
    }
  }

  public async retrieveLatest(
    subjectPrivateAddress: string,
    issuerPrivateAddress: string,
  ): Promise<Certificate | null> {
    const serialization = await this.retrieveLatestSerialization(
      subjectPrivateAddress,
      issuerPrivateAddress,
    );
    if (!serialization) {
      return null;
    }
    const certificate = Certificate.deserialize(serialization);
    return new Date() < certificate.expiryDate ? certificate : null;
  }

  public async retrieveAll(
    subjectPrivateAddress: string,
    issuerPrivateAddress: string,
  ): Promise<readonly Certificate[]> {
    const allCertificatesSerialized = await this.retrieveAllSerializations(
      subjectPrivateAddress,
      issuerPrivateAddress,
    );
    return allCertificatesSerialized
      .map((s) => Certificate.deserialize(s))
      .filter((c) => new Date() < c.expiryDate);
  }

  public abstract deleteExpired(): Promise<void>;

  protected abstract saveData(
    subjectPrivateAddress: string,
    subjectCertificateSerialized: ArrayBuffer,
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
