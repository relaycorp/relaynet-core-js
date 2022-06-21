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
exports.deserialize = exports.serialize = exports.MAX_SDU_PLAINTEXT_LENGTH = exports.RAMF_MAX_TTL = exports.MAX_RAMF_MESSAGE_LENGTH = void 0;
const asn1js = __importStar(require("asn1js"));
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const util_1 = require("util");
const asn1_1 = require("../asn1");
const cmsSignedData = __importStar(require("../crypto_wrappers/cms/signedData"));
const formatSignature_1 = require("../messages/formatSignature");
const RAMFSyntaxError_1 = __importDefault(require("./RAMFSyntaxError"));
const RAMFValidationError_1 = __importDefault(require("./RAMFValidationError"));
/**
 * Maximum length of any RAMF message per RS-001.
 *
 * https://specs.relaynet.network/RS-001
 */
exports.MAX_RAMF_MESSAGE_LENGTH = 9437184; // 9 MiB
const MAX_RECIPIENT_ADDRESS_LENGTH = 1024;
const MAX_ID_LENGTH = 64;
exports.RAMF_MAX_TTL = 15552000;
const MAX_PAYLOAD_LENGTH = 2 ** 23 - 1; // 8 MiB
const PRIVATE_ADDRESS_REGEX = /^[a-f0-9]+$/;
/**
 * Maximum length of any SDU to be encapsulated in a CMS EnvelopedData value, per the RAMF spec.
 */
exports.MAX_SDU_PLAINTEXT_LENGTH = 8322048;
const FORMAT_SIGNATURE_CONSTANT = Buffer.from('Relaynet');
const ASN1_SCHEMA = (0, asn1_1.makeHeterogeneousSequenceSchema)('RAMFMessage', [
    new asn1js.Primitive({ name: 'recipientAddress' }),
    new asn1js.Primitive({ name: 'id' }),
    new asn1js.Primitive({ name: 'date' }),
    new asn1js.Primitive({ name: 'ttl' }),
    new asn1js.Primitive({ name: 'payload' }),
]);
/**
 * Sign and encode the current message.
 *
 * @param message The message to serialize.
 * @param concreteMessageTypeOctet
 * @param concreteMessageVersionOctet
 * @param senderPrivateKey The private key to sign the message.
 * @param signatureOptions Any signature options.
 */
async function serialize(message, concreteMessageTypeOctet, concreteMessageVersionOctet, senderPrivateKey, signatureOptions) {
    //region Validation
    validateRecipientAddressLength(message.recipientAddress);
    validateMessageIdLength(message.id);
    validateTtl(message.ttl);
    validatePayloadLength(message.payloadSerialized);
    //endregion
    const formatSignature = (0, formatSignature_1.generateFormatSignature)(concreteMessageTypeOctet, concreteMessageVersionOctet);
    const fieldSetSerialized = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js.VisibleString({ value: message.recipientAddress }), new asn1js.VisibleString({ value: message.id }), (0, asn1_1.dateToASN1DateTimeInUTC)(message.creationDate), new asn1js.Integer({ value: message.ttl }), new asn1js.OctetString({ valueHex: (0, buffer_to_arraybuffer_1.default)(message.payloadSerialized) })).toBER();
    //region Signature
    const signature = await cmsSignedData.sign(fieldSetSerialized, senderPrivateKey, message.senderCertificate, message.senderCaCertificateChain, signatureOptions);
    //endregion
    // There doesn't seem to be an efficient way to concatenate ArrayBuffer instances, so we'll have
    // to make a copy of the signature (which already contains a copy of the payload). So by the end
    // of this function we'll need more than 3x the size of the payload in memory. This issue will
    // go away with https://github.com/relaynet/specs/issues/14
    const serialization = new ArrayBuffer(formatSignature.byteLength + signature.byteLength);
    const serializationView = new Uint8Array(serialization);
    serializationView.set(formatSignature, 0);
    serializationView.set(new Uint8Array(signature), formatSignature.byteLength);
    return serialization;
}
exports.serialize = serialize;
function validateMessageLength(serialization) {
    if (exports.MAX_RAMF_MESSAGE_LENGTH < serialization.byteLength) {
        throw new RAMFSyntaxError_1.default(`Message should not be longer than 9 MiB (got ${serialization.byteLength} octets)`);
    }
}
async function deserialize(serialization, concreteMessageTypeOctet, concreteMessageVersionOctet, messageClass) {
    validateMessageLength(serialization);
    const messageFormatSignature = parseMessageFormatSignature(serialization.slice(0, 10));
    validateFileFormatSignature(messageFormatSignature, concreteMessageTypeOctet, concreteMessageVersionOctet);
    const signatureVerification = await verifySignature(serialization.slice(10));
    const messageFields = parseMessageFields(signatureVerification.plaintext);
    validateRecipientAddressLength(messageFields.recipientAddress);
    validateRecipientAddress(messageFields.recipientAddress);
    validateMessageIdLength(messageFields.id);
    validateTtl(messageFields.ttl);
    validatePayloadLength(messageFields.payload);
    return new messageClass(messageFields.recipientAddress, signatureVerification.signerCertificate, messageFields.payload, {
        creationDate: messageFields.date,
        id: messageFields.id,
        senderCaCertificateChain: signatureVerification.attachedCertificates,
        ttl: messageFields.ttl,
    });
}
exports.deserialize = deserialize;
function decimalToHex(numberDecimal) {
    return '0x' + numberDecimal.toString(16);
}
//region Serialization and deserialization validation
function validateFileFormatSignature(messageFields, concreteMessageTypeOctet, concreteMessageVersionOctet) {
    //region Message type validation
    if (messageFields.concreteMessageType !== concreteMessageTypeOctet) {
        const expectedMessageTypeHex = decimalToHex(concreteMessageTypeOctet);
        const actualMessageTypeHex = decimalToHex(messageFields.concreteMessageType);
        throw new RAMFSyntaxError_1.default(`Expected concrete message type ${expectedMessageTypeHex} but got ${actualMessageTypeHex}`);
    }
    //endregion
    //region Message version validation
    if (messageFields.concreteMessageVersion !== concreteMessageVersionOctet) {
        const expectedVersionHex = decimalToHex(concreteMessageVersionOctet);
        const actualVersionHex = decimalToHex(messageFields.concreteMessageVersion);
        throw new RAMFSyntaxError_1.default(`Expected concrete message version ${expectedVersionHex} but got ${actualVersionHex}`);
    }
    //endregion
}
function validateRecipientAddress(recipientAddress) {
    try {
        // tslint:disable-next-line:no-unused-expression
        new URL(recipientAddress);
    }
    catch (_) {
        // The address isn't public. Check if it's private:
        if (!recipientAddress.match(PRIVATE_ADDRESS_REGEX)) {
            throw new RAMFValidationError_1.default(`Recipient address should be a valid node address (got: "${recipientAddress}")`);
        }
    }
}
function validateRecipientAddressLength(recipientAddress) {
    const length = recipientAddress.length;
    if (MAX_RECIPIENT_ADDRESS_LENGTH < length) {
        throw new RAMFSyntaxError_1.default(`Recipient address should not span more than ${MAX_RECIPIENT_ADDRESS_LENGTH} characters ` +
            `(got ${length})`);
    }
}
function validateMessageIdLength(messageId) {
    const length = messageId.length;
    if (MAX_ID_LENGTH < length) {
        throw new RAMFSyntaxError_1.default(`Id should not span more than ${MAX_ID_LENGTH} characters (got ${length})`);
    }
}
function validateTtl(ttl) {
    if (ttl < 0) {
        throw new RAMFSyntaxError_1.default('TTL cannot be negative');
    }
    if (exports.RAMF_MAX_TTL < ttl) {
        throw new RAMFSyntaxError_1.default(`TTL must be less than ${exports.RAMF_MAX_TTL} (got ${ttl})`);
    }
}
function validatePayloadLength(payloadBuffer) {
    const length = payloadBuffer.byteLength;
    if (MAX_PAYLOAD_LENGTH < length) {
        throw new RAMFSyntaxError_1.default(`Payload size must not exceed 8 MiB (got ${length} octets)`);
    }
}
//endregion
//region Deserialization validation
function parseMessageFormatSignature(serialization) {
    if (serialization.byteLength < 10) {
        throw new RAMFSyntaxError_1.default('Serialization is too small to contain RAMF format signature');
    }
    const formatSignature = Buffer.from(serialization.slice(0, 10));
    if (!FORMAT_SIGNATURE_CONSTANT.equals(formatSignature.slice(0, 8))) {
        throw new RAMFSyntaxError_1.default('RAMF format signature does not begin with "Relaynet"');
    }
    return { concreteMessageType: formatSignature[8], concreteMessageVersion: formatSignature[9] };
}
function parseMessageFields(serialization) {
    const result = asn1js.verifySchema(serialization, ASN1_SCHEMA);
    if (!result.verified) {
        throw new RAMFSyntaxError_1.default('Invalid RAMF fields');
    }
    const messageBlock = result.result.RAMFMessage;
    const textDecoder = new util_1.TextDecoder();
    const ttlBigInt = getIntegerFromPrimitiveBlock(messageBlock.ttl);
    return {
        date: getDateFromPrimitiveBlock(messageBlock.date),
        id: textDecoder.decode(messageBlock.id.valueBlock.valueHex),
        payload: Buffer.from(messageBlock.payload.valueBlock.valueHex),
        recipientAddress: textDecoder.decode(messageBlock.recipientAddress.valueBlock.valueHex),
        ttl: Number(ttlBigInt), // Cannot exceed Number.MAX_SAFE_INTEGER anyway
    };
}
function getDateFromPrimitiveBlock(block) {
    try {
        return (0, asn1_1.asn1DateTimeToDate)(block);
    }
    catch (exc) {
        throw new RAMFValidationError_1.default(exc, 'Message date is invalid');
    }
}
function getIntegerFromPrimitiveBlock(block) {
    const integerBlock = new asn1js.Integer({ valueHex: block.valueBlock.valueHexView });
    return integerBlock.toBigInt();
}
async function verifySignature(cmsSignedDataSerialized) {
    try {
        return await cmsSignedData.verifySignature(cmsSignedDataSerialized);
    }
    catch (error) {
        throw new RAMFValidationError_1.default(error, 'Invalid RAMF message signature');
    }
}
//endregion
//# sourceMappingURL=serialization.js.map