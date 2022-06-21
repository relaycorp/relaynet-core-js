import * as asn1js from 'asn1js';
import { CertificateRotation } from '../CertificateRotation';
import Parcel from '../Parcel';
import { ParcelCollectionAck } from '../ParcelCollectionAck';
import PayloadPlaintext from './PayloadPlaintext';
export interface MessageWithExpiryDate {
    readonly messageSerialized: ArrayBuffer;
    readonly expiryDate: Date;
}
export declare type CargoMessageSetItem = Parcel | ParcelCollectionAck | CertificateRotation;
/**
 * Plaintext representation of the payload in a cargo message.
 *
 * That is, the set of RAMF messages the cargo contains.
 */
export default class CargoMessageSet implements PayloadPlaintext {
    readonly messages: readonly ArrayBuffer[];
    /**
     * Maximum number of octets for any serialized message to be included in a cargo.
     *
     * This is the result of subtracting the TLVs for the SET and OCTET STRING values from the
     * maximum size of an SDU to be encrypted.
     */
    static readonly MAX_MESSAGE_LENGTH: number;
    static deserialize(serialization: ArrayBuffer): CargoMessageSet;
    /**
     * Deserialize a value if it's a legal item in a cargo message set.
     *
     * @param itemSerialized The parcel or PCA to be deserialized
     * @throws InvalidMessageError If `itemSerialized` is not a legal item in a cargo message set
     */
    static deserializeItem(itemSerialized: ArrayBuffer): Promise<CargoMessageSetItem>;
    static batchMessagesSerialized(messagesWithExpiryDate: AsyncIterable<MessageWithExpiryDate>): AsyncIterable<MessageWithExpiryDate>;
    protected static readonly ASN1_SCHEMA: asn1js.Sequence;
    constructor(messages: readonly ArrayBuffer[]);
    serialize(): ArrayBuffer;
}
