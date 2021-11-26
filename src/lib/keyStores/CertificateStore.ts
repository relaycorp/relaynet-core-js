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

  public async retrieveLatest(subjectPrivateAddress: string): Promise<Certificate> {
    throw new Error('implement' + subjectPrivateAddress);
  }

  public async retrieveAll(subjectPrivateAddress: string): Promise<readonly Certificate[]> {
    throw new Error('implement' + subjectPrivateAddress);
  }

  public async deleteExpired(): Promise<void> {
    throw new Error('implement');
  }

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

  protected abstract deleteExpiredData(): Promise<void>;
}
