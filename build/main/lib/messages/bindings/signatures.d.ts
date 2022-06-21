import { Signer } from '../../nodes/signatures/Signer';
import { Verifier } from '../../nodes/signatures/Verifier';
export declare class ParcelCollectionHandshakeSigner extends Signer {
    readonly oid: string;
}
export declare class ParcelDeliverySigner extends Signer {
    readonly oid: string;
}
export declare class ParcelCollectionHandshakeVerifier extends Verifier {
    readonly oid: string;
}
export declare class ParcelDeliveryVerifier extends Verifier {
    readonly oid: string;
}
