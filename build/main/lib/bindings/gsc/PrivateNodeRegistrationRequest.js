"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PrivateNodeRegistrationRequest = void 0;
const asn1js_1 = require("asn1js");
const asn1_1 = require("../../asn1");
const keys_1 = require("../../crypto_wrappers/keys");
const rsaSigning_1 = require("../../crypto_wrappers/rsaSigning");
const InvalidMessageError_1 = __importDefault(require("../../messages/InvalidMessageError"));
const oids_1 = require("../../oids");
class PrivateNodeRegistrationRequest {
    constructor(privateNodePublicKey, pnraSerialized) {
        this.privateNodePublicKey = privateNodePublicKey;
        this.pnraSerialized = pnraSerialized;
    }
    static async deserialize(serialization) {
        const result = (0, asn1js_1.verifySchema)(serialization, PrivateNodeRegistrationRequest.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError_1.default('Serialization is not a valid PrivateNodeRegistrationRequest');
        }
        const request = result.result.PrivateNodeRegistrationRequest;
        let privateNodePublicKey;
        try {
            privateNodePublicKey = await (0, keys_1.derDeserializeRSAPublicKey)(request.privateNodePublicKey.valueBlock.valueHex);
        }
        catch (err) {
            throw new InvalidMessageError_1.default('Private node public key is not valid', err);
        }
        const authorizationSerializedASN1 = request.pnraSerialized;
        const countersignature = request.countersignature.valueBlock.valueHex;
        const countersignaturePlaintext = PrivateNodeRegistrationRequest.makePNRACountersignaturePlaintext(authorizationSerializedASN1);
        if (!(await (0, rsaSigning_1.verify)(countersignature, privateNodePublicKey, countersignaturePlaintext))) {
            throw new InvalidMessageError_1.default('Authorization countersignature is invalid');
        }
        return new PrivateNodeRegistrationRequest(privateNodePublicKey, authorizationSerializedASN1.valueBlock.valueHex);
    }
    static makePNRACountersignaturePlaintext(pnraSerializedASN1) {
        return (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.ObjectIdentifier({
            value: oids_1.RELAYNET_OIDS.NODE_REGISTRATION.AUTHORIZATION_COUNTERSIGNATURE,
        }), pnraSerializedASN1).toBER();
    }
    async serialize(privateNodePrivateKey) {
        const privateNodePublicKeySerialized = await (0, keys_1.derSerializePublicKey)(this.privateNodePublicKey);
        const authorizationSerializedASN1 = new asn1js_1.OctetString({ valueHex: this.pnraSerialized });
        const countersignaturePlaintext = PrivateNodeRegistrationRequest.makePNRACountersignaturePlaintext(authorizationSerializedASN1);
        const signature = await (0, rsaSigning_1.sign)(countersignaturePlaintext, privateNodePrivateKey);
        return (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: privateNodePublicKeySerialized }), authorizationSerializedASN1, new asn1js_1.OctetString({ valueHex: signature })).toBER();
    }
}
exports.PrivateNodeRegistrationRequest = PrivateNodeRegistrationRequest;
PrivateNodeRegistrationRequest.SCHEMA = (0, asn1_1.makeHeterogeneousSequenceSchema)('PrivateNodeRegistrationRequest', [
    new asn1js_1.Primitive({ name: 'privateNodePublicKey' }),
    new asn1js_1.Primitive({ name: 'pnraSerialized' }),
    new asn1js_1.Primitive({ name: 'countersignature' }),
]);
//# sourceMappingURL=PrivateNodeRegistrationRequest.js.map