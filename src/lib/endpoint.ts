/* tslint:disable:max-classes-per-file */
import Certificate from './crypto_wrappers/x509/Certificate';
import Parcel from './Parcel';

export abstract class BaseEndpoint {
  constructor(protected readonly sessionStore: any) {}

  public abstract async deliverParcel(parcelSerialized: ArrayBuffer): Promise<void>;
}

export abstract class PrivateEndpoint extends BaseEndpoint {
  public abstract async collectParcels(): Promise<Parcel>;

  public abstract async requestCertificate(): Promise<Certificate>;

  // public abstract async revokePda(): Promise<void>;
}
