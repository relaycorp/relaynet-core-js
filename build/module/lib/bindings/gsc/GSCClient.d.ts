import { ParcelCollectionHandshakeSigner, ParcelDeliverySigner } from '../../messages/bindings/signatures';
import { ParcelCollection } from './ParcelCollection';
import { PrivateNodeRegistration } from './PrivateNodeRegistration';
import { StreamingMode } from './StreamingMode';
export interface GSCClient {
    readonly preRegisterNode: (nodePublicKey: CryptoKey) => Promise<ArrayBuffer>;
    readonly registerNode: (pnrrSerialized: ArrayBuffer) => Promise<PrivateNodeRegistration>;
    readonly deliverParcel: (parcelSerialized: ArrayBuffer, signer: ParcelDeliverySigner) => Promise<void>;
    readonly collectParcels: (nonceSigners: readonly ParcelCollectionHandshakeSigner[], streamingMode: StreamingMode, handshakeCallback?: () => void) => AsyncIterable<ParcelCollection>;
}
