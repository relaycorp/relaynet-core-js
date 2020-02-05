export interface CargoRelay {
  readonly relayId: string;
  readonly cargo: Buffer;
}

export interface CargoRelayClient {
  readonly close: () => void;

  readonly deliverCargo: (cargo: AsyncGenerator<CargoRelay>) => IterableIterator<string>;

  readonly collectCargo: () => readonly Buffer[];
}
