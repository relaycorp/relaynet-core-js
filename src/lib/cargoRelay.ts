/**
 * The local id of the cargo to be delivered.
 *
 * It can be a file name or DB primary key, for example.
 */
export type LocalCargoId = string;

export interface CargoDeliveryRequest {
  readonly localId: LocalCargoId;
  readonly cargo: Buffer;
}

export interface CargoRelayClient {
  readonly close: () => void;

  readonly deliverCargo: (
    cargo: IterableIterator<CargoDeliveryRequest>,
  ) => IterableIterator<LocalCargoId>;

  readonly collectCargo: () => readonly Buffer[];
}
