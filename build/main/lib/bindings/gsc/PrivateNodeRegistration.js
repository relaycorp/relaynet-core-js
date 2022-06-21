"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PrivateNodeRegistration = void 0;
const asn1js_1 = require("asn1js");
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const asn1_1 = require("../../asn1");
const keys_1 = require("../../crypto_wrappers/keys");
const Certificate_1 = __importDefault(require("../../crypto_wrappers/x509/Certificate"));
const InvalidMessageError_1 = __importDefault(require("../../messages/InvalidMessageError"));
class PrivateNodeRegistration {
    constructor(privateNodeCertificate, gatewayCertificate, sessionKey = null) {
        this.privateNodeCertificate = privateNodeCertificate;
        this.gatewayCertificate = gatewayCertificate;
        this.sessionKey = sessionKey;
    }
    static async deserialize(serialization) {
        const result = (0, asn1js_1.verifySchema)(serialization, PrivateNodeRegistration.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError_1.default('Serialization is not a valid PrivateNodeRegistration');
        }
        const registrationASN1 = result.result.PrivateNodeRegistration;
        let privateNodeCertificate;
        try {
            privateNodeCertificate = Certificate_1.default.deserialize(registrationASN1.privateNodeCertificate.valueBlock.valueHex);
        }
        catch (err) {
            throw new InvalidMessageError_1.default(err, 'Private node certificate is invalid');
        }
        let gatewayCertificate;
        try {
            gatewayCertificate = Certificate_1.default.deserialize(registrationASN1.gatewayCertificate.valueBlock.valueHex);
        }
        catch (err) {
            throw new InvalidMessageError_1.default(err, 'Gateway certificate is invalid');
        }
        const sessionKey = await deserializeSessionKey(registrationASN1.sessionKey);
        return new PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate, sessionKey);
    }
    async serialize() {
        let sessionKeySequence = null;
        if (this.sessionKey) {
            const sessionPublicKeySerialized = await (0, keys_1.derSerializePublicKey)(this.sessionKey.publicKey);
            sessionKeySequence = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: (0, buffer_to_arraybuffer_1.default)(this.sessionKey.keyId) }), new asn1js_1.OctetString({ valueHex: (0, buffer_to_arraybuffer_1.default)(sessionPublicKeySerialized) }));
        }
        return (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: this.privateNodeCertificate.serialize() }), new asn1js_1.OctetString({ valueHex: this.gatewayCertificate.serialize() }), ...(sessionKeySequence ? [sessionKeySequence] : [])).toBER();
    }
}
exports.PrivateNodeRegistration = PrivateNodeRegistration;
PrivateNodeRegistration.SCHEMA = (0, asn1_1.makeHeterogeneousSequenceSchema)('PrivateNodeRegistration', [
    new asn1js_1.Primitive({ name: 'privateNodeCertificate' }),
    new asn1js_1.Primitive({ name: 'gatewayCertificate' }),
    new asn1js_1.Constructed({
        name: 'sessionKey',
        optional: true,
        value: [
            new asn1js_1.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 } }),
            new asn1js_1.Primitive({ idBlock: { tagClass: 3, tagNumber: 1 } }),
        ],
    }),
]);
async function deserializeSessionKey(sessionKeySequence) {
    if (!sessionKeySequence) {
        return null;
    }
    if (sessionKeySequence.valueBlock.value.length < 2) {
        throw new InvalidMessageError_1.default('Session key SEQUENCE should have at least 2 items');
    }
    const sessionPublicKeyASN1 = sessionKeySequence.valueBlock.value[1];
    const sessionKeyIdASN1 = sessionKeySequence.valueBlock.value[0];
    let sessionPublicKey;
    try {
        sessionPublicKey = await (0, keys_1.derDeserializeECDHPublicKey)(sessionPublicKeyASN1.valueBlock.valueHex);
    }
    catch (err) {
        throw new InvalidMessageError_1.default(new Error(err), // The original error could be a string 🤦
        'Session key is not a valid ECDH public key');
    }
    return {
        keyId: Buffer.from(sessionKeyIdASN1.valueBlock.valueHex),
        publicKey: sessionPublicKey,
    };
}
//# sourceMappingURL=PrivateNodeRegistration.js.map