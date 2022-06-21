"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const uuid4_1 = __importDefault(require("uuid4"));
const _utils_1 = require("../_utils");
const envelopedData_1 = require("../crypto_wrappers/cms/envelopedData");
const PrivateKeyStore_1 = require("../keyStores/PrivateKeyStore");
const RAMFError_1 = __importDefault(require("../ramf/RAMFError"));
const InvalidMessageError_1 = __importDefault(require("./InvalidMessageError"));
const RecipientAddressType_1 = require("./RecipientAddressType");
const DEFAULT_TTL_SECONDS = 5 * 60; // 5 minutes
const PRIVATE_ADDRESS_REGEX = /^0[a-f\d]+$/;
/**
 * Relaynet Abstract Message Format, version 1.
 */
class RAMFMessage {
    constructor(recipientAddress, senderCertificate, payloadSerialized, options = {}) {
        this.recipientAddress = recipientAddress;
        this.senderCertificate = senderCertificate;
        this.payloadSerialized = payloadSerialized;
        this.id = options.id || (0, uuid4_1.default)();
        this.creationDate = (0, _utils_1.makeDateWithSecondPrecision)(options.creationDate);
        this.ttl = options.ttl !== undefined ? options.ttl : DEFAULT_TTL_SECONDS;
        this.senderCaCertificateChain =
            options.senderCaCertificateChain?.filter((c) => !c.isEqual(senderCertificate)) ?? [];
    }
    get expiryDate() {
        const creationDateTimestamp = this.creationDate.getTime();
        return new Date(creationDateTimestamp + this.ttl * 1000);
    }
    get isRecipientAddressPrivate() {
        try {
            // tslint:disable-next-line:no-unused-expression
            new URL(this.recipientAddress);
        }
        catch (_) {
            return true;
        }
        return false;
    }
    /**
     * Return certification path between sender's certificate and one certificate in
     * `trustedCertificates`.
     *
     * @param trustedCertificates
     */
    async getSenderCertificationPath(trustedCertificates) {
        return this.senderCertificate.getCertificationPath(this.senderCaCertificateChain, trustedCertificates);
    }
    async unwrapPayload(privateKeyOrStore, privateAddress) {
        if (privateKeyOrStore instanceof PrivateKeyStore_1.PrivateKeyStore &&
            !this.isRecipientAddressPrivate &&
            !privateAddress) {
            throw new RAMFError_1.default('Recipient private address should be passed because message uses public address');
        }
        const payloadEnvelopedData = envelopedData_1.EnvelopedData.deserialize((0, buffer_to_arraybuffer_1.default)(this.payloadSerialized));
        if (!(payloadEnvelopedData instanceof envelopedData_1.SessionEnvelopedData)) {
            throw new RAMFError_1.default('Sessionless payloads are no longer supported');
        }
        const payloadPlaintext = await this.decryptPayload(payloadEnvelopedData, privateKeyOrStore, privateAddress);
        const payload = await this.deserializePayload(payloadPlaintext);
        const senderSessionKey = await payloadEnvelopedData.getOriginatorKey();
        return { payload, senderSessionKey };
    }
    /**
     * Report whether the message is valid.
     *
     * @param recipientAddressType The expected type of recipient address, if one is required
     * @param trustedCertificates If present, will check that the sender is authorized to send
     *   the message based on the trusted certificates.
     * @return The certification path from the sender to one of the `trustedCertificates` (if present)
     */
    async validate(recipientAddressType, trustedCertificates) {
        await this.validateRecipientAddress(recipientAddressType);
        await this.validateTiming();
        if (trustedCertificates) {
            return this.validateAuthorization(trustedCertificates);
        }
        this.senderCertificate.validate();
        return null;
    }
    async decryptPayload(payloadEnvelopedData, privateKeyOrStore, privateAddress) {
        const privateKey = await this.fetchPrivateKey(payloadEnvelopedData, privateKeyOrStore, privateAddress);
        return payloadEnvelopedData.decrypt(privateKey);
    }
    async fetchPrivateKey(payloadEnvelopedData, privateKeyOrStore, privateAddress) {
        const keyId = payloadEnvelopedData.getRecipientKeyId();
        let privateKey;
        if (privateKeyOrStore instanceof PrivateKeyStore_1.PrivateKeyStore) {
            const peerPrivateAddress = await this.senderCertificate.calculateSubjectPrivateAddress();
            privateKey = await privateKeyOrStore.retrieveSessionKey(keyId, privateAddress ?? this.recipientAddress, peerPrivateAddress);
        }
        else {
            privateKey = privateKeyOrStore;
        }
        return privateKey;
    }
    async validateRecipientAddress(requiredRecipientAddressType) {
        const isAddressPrivate = this.isRecipientAddressPrivate;
        if (isAddressPrivate && !PRIVATE_ADDRESS_REGEX[Symbol.match](this.recipientAddress)) {
            throw new InvalidMessageError_1.default('Recipient address is malformed');
        }
        if (requiredRecipientAddressType === RecipientAddressType_1.RecipientAddressType.PUBLIC && isAddressPrivate) {
            throw new InvalidMessageError_1.default('Recipient address should be public but got a private one');
        }
        if (requiredRecipientAddressType === RecipientAddressType_1.RecipientAddressType.PRIVATE && !isAddressPrivate) {
            throw new InvalidMessageError_1.default('Recipient address should be private but got a public one');
        }
    }
    async validateAuthorization(trustedCertificates) {
        let certificationPath;
        try {
            certificationPath = await this.getSenderCertificationPath(trustedCertificates);
        }
        catch (error) {
            throw new InvalidMessageError_1.default(error, 'Sender is not authorized');
        }
        if (this.isRecipientAddressPrivate) {
            const recipientCertificate = certificationPath[1];
            const recipientPrivateAddress = await recipientCertificate.calculateSubjectPrivateAddress();
            if (recipientPrivateAddress !== this.recipientAddress) {
                throw new InvalidMessageError_1.default(`Sender is not authorized to reach ${this.recipientAddress}`);
            }
        }
        return certificationPath;
    }
    async validateTiming() {
        const currentDate = new Date();
        if (currentDate < this.creationDate) {
            throw new InvalidMessageError_1.default('Message date is in the future');
        }
        if (this.expiryDate < currentDate) {
            throw new InvalidMessageError_1.default('Message already expired');
        }
    }
}
exports.default = RAMFMessage;
//# sourceMappingURL=RAMFMessage.js.map