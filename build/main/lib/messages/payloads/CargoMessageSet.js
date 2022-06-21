"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const asn1js = __importStar(require("asn1js"));
const asn1_1 = require("../../asn1");
const serialization_1 = require("../../ramf/serialization");
const CertificateRotation_1 = require("../CertificateRotation");
const InvalidMessageError_1 = __importDefault(require("../InvalidMessageError"));
const Parcel_1 = __importDefault(require("../Parcel"));
const ParcelCollectionAck_1 = require("../ParcelCollectionAck");
/**
 * Number of octets needed to represent the type and length of an 8 MiB value in DER.
 */
const DER_TL_OVERHEAD_OCTETS = 5;
/**
 * Plaintext representation of the payload in a cargo message.
 *
 * That is, the set of RAMF messages the cargo contains.
 */
class CargoMessageSet {
    constructor(messages) {
        this.messages = messages;
    }
    static deserialize(serialization) {
        const result = asn1js.verifySchema(serialization, CargoMessageSet.ASN1_SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError_1.default('Serialization is not a valid CargoMessageSet');
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
            throw new InvalidMessageError_1.default(error, 'Value is not a valid Cargo Message Set item');
        }
    }
    static async *batchMessagesSerialized(messagesWithExpiryDate) {
        // tslint:disable-next-line:readonly-array no-let
        let currentBatch = [];
        // tslint:disable-next-line:no-let no-unnecessary-initializer
        let currentBatchExpiryDate = undefined;
        // tslint:disable-next-line:no-let
        let availableOctetsInCurrentBatch = serialization_1.MAX_SDU_PLAINTEXT_LENGTH - DER_TL_OVERHEAD_OCTETS;
        for await (const { messageSerialized, expiryDate } of messagesWithExpiryDate) {
            if (CargoMessageSet.MAX_MESSAGE_LENGTH < messageSerialized.byteLength) {
                throw new InvalidMessageError_1.default(`Cargo messages must not exceed ${CargoMessageSet.MAX_MESSAGE_LENGTH} octets ` +
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
                availableOctetsInCurrentBatch = serialization_1.MAX_SDU_PLAINTEXT_LENGTH - messageTlvLength;
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
    serialize() {
        const messagesSerialized = Array.from(this.messages).map((m) => new asn1js.OctetString({ valueHex: m }));
        return (0, asn1_1.derSerializeHomogeneousSequence)(messagesSerialized);
    }
}
exports.default = CargoMessageSet;
/**
 * Maximum number of octets for any serialized message to be included in a cargo.
 *
 * This is the result of subtracting the TLVs for the SET and OCTET STRING values from the
 * maximum size of an SDU to be encrypted.
 */
CargoMessageSet.MAX_MESSAGE_LENGTH = serialization_1.MAX_SDU_PLAINTEXT_LENGTH - DER_TL_OVERHEAD_OCTETS * 2;
CargoMessageSet.ASN1_SCHEMA = new asn1js.Sequence({
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
function getItemClass(itemSerialized) {
    const messageFormatSignature = Buffer.from(itemSerialized.slice(0, 10));
    if (messageFormatSignature.equals(ParcelCollectionAck_1.ParcelCollectionAck.FORMAT_SIGNATURE)) {
        return ParcelCollectionAck_1.ParcelCollectionAck;
    }
    if (messageFormatSignature.equals(CertificateRotation_1.CERTIFICATE_ROTATION_FORMAT_SIGNATURE)) {
        return CertificateRotation_1.CertificateRotation;
    }
    return Parcel_1.default;
}
//# sourceMappingURL=CargoMessageSet.js.map