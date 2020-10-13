import Certificate from '../../../crypto_wrappers/x509/Certificate';

export class ParcelCollection {
  constructor(
    public readonly parcelSerialized: ArrayBuffer,
    public readonly trustedCertificates: readonly Certificate[],
    private readonly ackCallback: () => Promise<void>,
  ) {}

  public async ack(): Promise<void> {
    await this.ackCallback();
  }

  public async deserializeAndValidateParcel(): Promise<void> {
    return undefined;
  }
}
