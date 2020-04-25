export interface ParcelCollection {
  readonly originEndpointPrivateAddress: string;
  readonly parcelId: string;
}

export class ParcelCollectionAcknowledgement {
  public static deserialize(_pcaSerialized: ArrayBuffer): ParcelCollectionAcknowledgement {
    throw new Error('Implement!');
  }

  constructor(public collections: readonly ParcelCollection[]) {
    // TODO: Implement
  }

  public serialize(): ArrayBuffer {
    throw new Error('Implement!');
  }
}
