"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PrivateNodeRegistrationAuthorization = void 0;
const asn1js_1 = require("asn1js");
const asn1_1 = require("../../asn1");
const rsaSigning_1 = require("../../crypto_wrappers/rsaSigning");
const InvalidMessageError_1 = __importDefault(require("../../messages/InvalidMessageError"));
const oids_1 = require("../../oids");
class PrivateNodeRegistrationAuthorization {
    constructor(expiryDate, gatewayData) {
        this.expiryDate = expiryDate;
        this.gatewayData = gatewayData;
    }
    static async deserialize(serialization, gatewayPublicKey) {
        const result = (0, asn1js_1.verifySchema)(serialization, PrivateNodeRegistrationAuthorization.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError_1.default('Serialization is not a valid PrivateNodeRegistrationAuthorization');
        }
        const authorizationASN1 = result.result.PrivateNodeRegistrationAuthorization;
        const expiryDate = (0, asn1_1.asn1DateTimeToDate)(authorizationASN1.expiryDate);
        if (expiryDate < new Date()) {
            throw new InvalidMessageError_1.default('Authorization already expired');
        }
        const expectedSignaturePlaintext = PrivateNodeRegistrationAuthorization.makeSignaturePlaintext(authorizationASN1.expiryDate, authorizationASN1.gatewayData);
        const isSignatureValid = await (0, rsaSigning_1.verify)(authorizationASN1.signature.valueBlock.valueHex, gatewayPublicKey, expectedSignaturePlaintext);
        if (!isSignatureValid) {
            throw new InvalidMessageError_1.default('Authorization signature is invalid');
        }
        const gatewayData = authorizationASN1.gatewayData.valueBlock.valueHex;
        return new PrivateNodeRegistrationAuthorization(expiryDate, gatewayData);
    }
    static makeSignaturePlaintext(expiryDateASN1, gatewayDataASN1) {
        return (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.ObjectIdentifier({ value: oids_1.RELAYNET_OIDS.NODE_REGISTRATION.AUTHORIZATION }), expiryDateASN1, gatewayDataASN1).toBER();
    }
    async serialize(gatewayPrivateKey) {
        const expiryDateASN1 = (0, asn1_1.dateToASN1DateTimeInUTC)(this.expiryDate);
        const gatewayDataASN1 = new asn1js_1.OctetString({ valueHex: this.gatewayData });
        const signaturePlaintext = PrivateNodeRegistrationAuthorization.makeSignaturePlaintext(expiryDateASN1, gatewayDataASN1);
        const signature = await (0, rsaSigning_1.sign)(signaturePlaintext, gatewayPrivateKey);
        return (0, asn1_1.makeImplicitlyTaggedSequence)(expiryDateASN1, gatewayDataASN1, new asn1js_1.OctetString({ valueHex: signature })).toBER();
    }
}
exports.PrivateNodeRegistrationAuthorization = PrivateNodeRegistrationAuthorization;
PrivateNodeRegistrationAuthorization.SCHEMA = (0, asn1_1.makeHeterogeneousSequenceSchema)('PrivateNodeRegistrationAuthorization', [
    new asn1js_1.Primitive({ name: 'expiryDate' }),
    new asn1js_1.Primitive({ name: 'gatewayData' }),
    new asn1js_1.Primitive({ name: 'signature' }),
]);
//# sourceMappingURL=PrivateNodeRegistrationAuthorization.js.map