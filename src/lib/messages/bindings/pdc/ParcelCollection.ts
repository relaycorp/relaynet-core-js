import Certificate from '../../../crypto_wrappers/x509/Certificate';
import Parcel from '../../Parcel';
import { RecipientAddressType } from '../../RecipientAddressType';

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
    await parcel.validate(RecipientAddressType.PRIVATE, this.trustedCertificates);
    return parcel;
  }
}
