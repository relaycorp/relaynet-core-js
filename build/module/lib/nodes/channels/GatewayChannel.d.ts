/// <reference types="node" />
import { CargoMessageStream } from '../CargoMessageStream';
import { Channel } from './Channel';
/**
 * Channel whose node is a gateway.
 */
export declare abstract class GatewayChannel extends Channel {
    generateCargoes(messages: CargoMessageStream): AsyncIterable<Buffer>;
    protected encryptPayload(payloadPlaintext: ArrayBuffer): Promise<Buffer>;
}
