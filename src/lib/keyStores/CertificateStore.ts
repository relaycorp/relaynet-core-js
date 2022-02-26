import Certificate from '../crypto_wrappers/x509/Certificate';

export enum CertificateScope {
  PDA = 'pda',
  CDA = 'cda',
}

/**
 * Store of certificates.
 */
export abstract class CertificateStore {
  /**
   * Store `certificate` as long as it's still valid.
   *
   * @param certificate
   * @param scope
   */
  public async save(certificate: Certificate, scope: CertificateScope): Promise<void> {
    if (new Date() < certificate.expiryDate) {
      await this.saveData(
        await certificate.calculateSubjectPrivateAddress(),
        certificate.serialize(),
        certificate.expiryDate,
        scope,
      );
    }
  }

  public async retrieveLatest(
    subjectPrivateAddress: string,
    scope: CertificateScope,
  ): Promise<Certificate | null> {
    const serialization = await this.retrieveLatestSerialization(subjectPrivateAddress, scope);
    if (!serialization) {
      return null;
    }
    const certificate = Certificate.deserialize(serialization);
    return new Date() < certificate.expiryDate ? certificate : null;
  }

  public async retrieveAll(
    subjectPrivateAddress: string,
    scope: CertificateScope,
  ): Promise<readonly Certificate[]> {
    const allCertificatesSerialized = await this.retrieveAllSerializations(
      subjectPrivateAddress,
      scope,
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
    scope: CertificateScope,
  ): Promise<void>;

  protected abstract retrieveLatestSerialization(
    subjectPrivateAddress: string,
    scope: CertificateScope,
  ): Promise<ArrayBuffer | null>;

  protected abstract retrieveAllSerializations(
    subjectPrivateAddress: string,
    scope: CertificateScope,
  ): Promise<readonly ArrayBuffer[]>;
}
