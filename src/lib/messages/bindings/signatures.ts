// tslint:disable:max-classes-per-file

import { Signer } from '../../nodes/signatures/Signer';
import { Verifier } from '../../nodes/signatures/Verifier';
import { RELAYNET_OIDS } from '../../oids';

export class ParcelCollectionHandshakeSigner extends Signer {
  public readonly oid = RELAYNET_OIDS.SIGNATURE.PARCEL_COLLECTION_HANDSHAKE;
}

export class ParcelDeliverySigner extends Signer {
  public readonly oid = RELAYNET_OIDS.SIGNATURE.PARCEL_DELIVERY;
}

export class ParcelCollectionHandshakeVerifier extends Verifier {
  public readonly oid = RELAYNET_OIDS.SIGNATURE.PARCEL_COLLECTION_HANDSHAKE;
}

export class ParcelDeliveryVerifier extends Verifier {
  public readonly oid = RELAYNET_OIDS.SIGNATURE.PARCEL_DELIVERY;
}
