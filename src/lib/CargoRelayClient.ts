export interface CargoRelayClient {
  readonly close: () => void;
  readonly deliverCargo: (cargoSerialized: readonly Buffer[]) => void;
  readonly collectCargo: () => readonly Buffer[];
}
