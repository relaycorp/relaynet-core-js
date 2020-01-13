/* tslint:disable:max-classes-per-file */
import { EncryptionOptions } from './crypto_wrappers/cms/envelopedData';
import { SignatureOptions } from './crypto_wrappers/cms/signedData';
import Certificate from './crypto_wrappers/x509/Certificate';
import Parcel from './Parcel';
import { MessageOptions } from './ramf/Message';
import ServiceMessage from './ramf/ServiceMessage';

interface EndpointOptions {
  readonly encryptionOptions: EncryptionOptions;
  readonly sessionStore: any;
  readonly signatureOptions: SignatureOptions;
}

interface EndpointKeyPair {
  readonly privateKey: CryptoKey;
  readonly publicKeyCertificate: Certificate;
}

export abstract class BaseEndpoint<Message extends ServiceMessage> {
  constructor(
    protected readonly keyPair: EndpointKeyPair,
    protected readonly serviceMessageSerializer: any,
    protected readonly options: Partial<EndpointOptions> = {},
  ) {}

  // TODO: Should actually be concrete and call deliverParcel()
  public abstract async deliverMessage(
    message: Message,
    recipientAddress: string,
    recipientCertificate: Certificate,
    parcelOptions: Partial<MessageOptions>,
  ): Promise<void>;

  protected abstract async deliverParcel(
    parcelSerialized: ArrayBuffer,
    recipientPublicAddress: string,
  ): Promise<void>;

  protected abstract isParcelRecipientValid(recipientAddress: string): boolean;
}

export abstract class PrivateEndpoint extends BaseEndpoint<any> {
  public abstract async collectParcels(): Promise<Generator<Parcel>>;

  public abstract async requestCertificate(): Promise<Certificate>;

  public abstract async revokePda(pda: Certificate): Promise<void>;
}

export abstract class InternetEndpoint extends BaseEndpoint<any> {

}
