import { Signer } from '../../messages/bindings/Signer';
import { ParcelCollection } from './ParcelCollection';
import { PrivateNodeRegistration } from './PrivateNodeRegistration';
import { StreamingMode } from './StreamingMode';

export interface GSCClient {
  readonly preRegisterNode: (nodePublicKey: CryptoKey) => Promise<ArrayBuffer>;

  readonly registerNode: (pnrrSerialized: ArrayBuffer) => Promise<PrivateNodeRegistration>;

  readonly deliverParcel: (parcelSerialized: ArrayBuffer, signer: Signer) => Promise<void>;

  readonly collectParcels: (
    nonceSigners: readonly Signer[],
    streamingMode: StreamingMode,
  ) => AsyncIterable<ParcelCollection>;
}
