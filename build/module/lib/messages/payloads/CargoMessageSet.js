import * as asn1js from 'asn1js';
import { derSerializeHomogeneousSequence } from '../../asn1';
import { MAX_SDU_PLAINTEXT_LENGTH } from '../../ramf/serialization';
import { CERTIFICATE_ROTATION_FORMAT_SIGNATURE, CertificateRotation } from '../CertificateRotation';
import InvalidMessageError from '../InvalidMessageError';
import Parcel from '../Parcel';
import { ParcelCollectionAck } from '../ParcelCollectionAck';
/**
 * Number of octets needed to represent the type and length of an 8 MiB value in DER.
 */
const DER_TL_OVERHEAD_OCTETS = 5;
/**
 * Plaintext representation of the payload in a cargo message.
 *
 * That is, the set of RAMF messages the cargo contains.
 */
export default class CargoMessageSet {
    messages;
    /**
     * Maximum number of octets for any serialized message to be included in a cargo.
     *
     * This is the result of subtracting the TLVs for the SET and OCTET STRING values from the
     * maximum size of an SDU to be encrypted.
     */
    static MAX_MESSAGE_LENGTH = MAX_SDU_PLAINTEXT_LENGTH - DER_TL_OVERHEAD_OCTETS * 2;
    static deserialize(serialization) {
        const result = asn1js.verifySchema(serialization, CargoMessageSet.ASN1_SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError('Serialization is not a valid CargoMessageSet');
        }
        const messageSet = result.result.message_set || [];
        const messages = messageSet.map((v) => v.valueBlock.valueHex);
        return new CargoMessageSet(messages);
    }
    /**
     * Deserialize a value if it's a legal item in a cargo message set.
     *
     * @param itemSerialized The parcel or PCA to be deserialized
     * @throws InvalidMessageError If `itemSerialized` is not a legal item in a cargo message set
     */
    static async deserializeItem(itemSerialized) {
        const messageClass = getItemClass(itemSerialized);
        try {
            return await messageClass.deserialize(itemSerialized);
        }
        catch (error) {
            throw new InvalidMessageError(error, 'Value is not a valid Cargo Message Set item');
        }
    }
    static async *batchMessagesSerialized(messagesWithExpiryDate) {
        // tslint:disable-next-line:readonly-array no-let
        let currentBatch = [];
        // tslint:disable-next-line:no-let no-unnecessary-initializer
        let currentBatchExpiryDate = undefined;
        // tslint:disable-next-line:no-let
        let availableOctetsInCurrentBatch = MAX_SDU_PLAINTEXT_LENGTH - DER_TL_OVERHEAD_OCTETS;
        for await (const { messageSerialized, expiryDate } of messagesWithExpiryDate) {
            if (CargoMessageSet.MAX_MESSAGE_LENGTH < messageSerialized.byteLength) {
                throw new InvalidMessageError(`Cargo messages must not exceed ${CargoMessageSet.MAX_MESSAGE_LENGTH} octets ` +
                    `(got one with ${messageSerialized.byteLength} octets)`);
            }
            currentBatchExpiryDate = currentBatchExpiryDate ?? expiryDate;
            const messageTlvLength = DER_TL_OVERHEAD_OCTETS + messageSerialized.byteLength;
            const messageFitsInCurrentBatch = messageTlvLength <= availableOctetsInCurrentBatch;
            if (messageFitsInCurrentBatch) {
                currentBatch.push(messageSerialized);
                currentBatchExpiryDate =
                    currentBatchExpiryDate < expiryDate ? expiryDate : currentBatchExpiryDate;
                availableOctetsInCurrentBatch -= messageTlvLength;
            }
            else {
                const cargoMessageSet = new CargoMessageSet(currentBatch);
                yield {
                    expiryDate: currentBatchExpiryDate,
                    messageSerialized: cargoMessageSet.serialize(),
                };
                currentBatch = [messageSerialized];
                currentBatchExpiryDate = expiryDate;
                availableOctetsInCurrentBatch = MAX_SDU_PLAINTEXT_LENGTH - messageTlvLength;
            }
        }
        if (currentBatch.length) {
            const cargoMessageSet = new CargoMessageSet(currentBatch);
            yield {
                expiryDate: currentBatchExpiryDate,
                messageSerialized: cargoMessageSet.serialize(),
            };
        }
    }
    static ASN1_SCHEMA = new asn1js.Sequence({
        name: 'CargoMessages',
        // @ts-ignore
        value: [
            new asn1js.Repeated({
                name: 'message_set',
                // @ts-ignore
                value: new asn1js.OctetString({ name: 'message' }),
            }),
        ],
    });
    constructor(messages) {
        this.messages = messages;
    }
    serialize() {
        const messagesSerialized = Array.from(this.messages).map((m) => new asn1js.OctetString({ valueHex: m }));
        return derSerializeHomogeneousSequence(messagesSerialized);
    }
}
function getItemClass(itemSerialized) {
    const messageFormatSignature = Buffer.from(itemSerialized.slice(0, 10));
    if (messageFormatSignature.equals(ParcelCollectionAck.FORMAT_SIGNATURE)) {
        return ParcelCollectionAck;
    }
    if (messageFormatSignature.equals(CERTIFICATE_ROTATION_FORMAT_SIGNATURE)) {
        return CertificateRotation;
    }
    return Parcel;
}
//# sourceMappingURL=CargoMessageSet.js.map