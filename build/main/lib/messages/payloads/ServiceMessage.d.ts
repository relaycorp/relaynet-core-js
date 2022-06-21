/// <reference types="node" />
import PayloadPlaintext from './PayloadPlaintext';
/**
 * Service message as encapsulated in a parcel.
 */
export default class ServiceMessage implements PayloadPlaintext {
    readonly type: string;
    readonly content: Buffer;
    /**
     * Initialize a service message from the `serialization`.
     *
     * @param serialization
     */
    static deserialize(serialization: ArrayBuffer): ServiceMessage;
    private static readonly SCHEMA;
    constructor(type: string, content: Buffer);
    /**
     * Serialize service message.
     */
    serialize(): ArrayBuffer;
}
