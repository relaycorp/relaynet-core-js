/// <reference types="node" />
/**
 * The local id of the cargo to be delivered.
 *
 * It can be a file name or DB primary key, for example.
 */
export declare type LocalCargoId = string;
/**
 * Request to deliver a cargo.
 */
export interface CargoDeliveryRequest {
    readonly localId: LocalCargoId;
    readonly cargo: Buffer;
}
/** Interface for cargo relay clients */
export interface CargoRelayClient {
    /** Close the underlying connection, if applicable */
    readonly close: () => void;
    /**
     *  Deliver the cargo yielded by the input iterator and return the local ids of the acknowledged
     *  deliveries
     */
    readonly deliverCargo: (cargo: IterableIterator<CargoDeliveryRequest>) => IterableIterator<LocalCargoId>;
    /** Collect and return cargo */
    readonly collectCargo: () => readonly Buffer[];
}
