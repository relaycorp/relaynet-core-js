import { Certificate } from '../../crypto/x509/Certificate';
import { Parcel } from '../../messages/Parcel';

export class ParcelCollection {
  constructor(
    public readonly parcelSerialized: ArrayBuffer,
    public readonly trustedCertificates: readonly Certificate[],
    private readonly ackCallback: () => Promise<void>,
  ) {}

  public async ack(): Promise<void> {
    await this.ackCallback();
  }

  public async deserializeAndValidateParcel(): Promise<Parcel> {
    const parcel = await Parcel.deserialize(this.parcelSerialized);
    await parcel.validate(this.trustedCertificates);
    return parcel;
  }
}
