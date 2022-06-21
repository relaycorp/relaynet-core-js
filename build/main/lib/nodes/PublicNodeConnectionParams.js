"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PublicNodeConnectionParams = void 0;
const asn1js_1 = require("asn1js");
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const is_valid_domain_1 = __importDefault(require("is-valid-domain"));
const util_1 = require("util");
const asn1_1 = require("../asn1");
const keys_1 = require("../crypto_wrappers/keys");
const errors_1 = require("./errors");
class PublicNodeConnectionParams {
    constructor(publicAddress, identityKey, sessionKey) {
        this.publicAddress = publicAddress;
        this.identityKey = identityKey;
        this.sessionKey = sessionKey;
    }
    static async deserialize(serialization) {
        const result = (0, asn1js_1.verifySchema)(serialization, PublicNodeConnectionParams.SCHEMA);
        if (!result.verified) {
            throw new errors_1.InvalidPublicNodeConnectionParams('Serialization is not a valid PublicNodeConnectionParams');
        }
        const paramsASN1 = result.result.PublicNodeConnectionParams;
        const textDecoder = new util_1.TextDecoder();
        const publicAddress = textDecoder.decode(paramsASN1.publicAddress.valueBlock.valueHex);
        if (!(0, is_valid_domain_1.default)(publicAddress)) {
            throw new errors_1.InvalidPublicNodeConnectionParams(`Public address is syntactically invalid (${publicAddress})`);
        }
        let identityKey;
        try {
            identityKey = await (0, keys_1.derDeserializeRSAPublicKey)(paramsASN1.identityKey.valueBlock.valueHex);
        }
        catch (err) {
            throw new errors_1.InvalidPublicNodeConnectionParams(new Error(err), // The original error could be a string 🤦
            'Identity key is not a valid RSA public key');
        }
        const sessionKeySequence = paramsASN1.sessionKey;
        if (sessionKeySequence.valueBlock.value.length < 2) {
            throw new errors_1.InvalidPublicNodeConnectionParams('Session key should have at least two items');
        }
        const sessionKeyId = sessionKeySequence.valueBlock.value[0].valueBlock.valueHex;
        const sessionPublicKeyASN1 = sessionKeySequence.valueBlock.value[1];
        let sessionPublicKey;
        try {
            sessionPublicKey = await (0, keys_1.derDeserializeECDHPublicKey)(sessionPublicKeyASN1.valueBlock.valueHex);
        }
        catch (err) {
            throw new errors_1.InvalidPublicNodeConnectionParams(new Error(err), // The original error could be a string 🤦
            'Session key is not a valid ECDH public key');
        }
        return new PublicNodeConnectionParams(publicAddress, identityKey, {
            keyId: Buffer.from(sessionKeyId),
            publicKey: sessionPublicKey,
        });
    }
    async serialize() {
        const identityKeySerialized = await (0, keys_1.derSerializePublicKey)(this.identityKey);
        const sessionPublicKeySerialized = await (0, keys_1.derSerializePublicKey)(this.sessionKey.publicKey);
        const sessionKeySequence = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: (0, buffer_to_arraybuffer_1.default)(this.sessionKey.keyId) }), new asn1js_1.OctetString({ valueHex: (0, buffer_to_arraybuffer_1.default)(sessionPublicKeySerialized) }));
        return (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.VisibleString({ value: this.publicAddress }), new asn1js_1.OctetString({ valueHex: (0, buffer_to_arraybuffer_1.default)(identityKeySerialized) }), sessionKeySequence).toBER();
    }
}
exports.PublicNodeConnectionParams = PublicNodeConnectionParams;
PublicNodeConnectionParams.SCHEMA = (0, asn1_1.makeHeterogeneousSequenceSchema)('PublicNodeConnectionParams', [
    new asn1js_1.Primitive({ name: 'publicAddress' }),
    new asn1js_1.Primitive({ name: 'identityKey' }),
    new asn1js_1.Constructed({
        name: 'sessionKey',
        value: [
            new asn1js_1.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 } }),
            new asn1js_1.Primitive({ idBlock: { tagClass: 3, tagNumber: 1 } }),
        ],
    }),
]);
//# sourceMappingURL=PublicNodeConnectionParams.js.map