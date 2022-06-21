"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertificationPath = void 0;
const asn1js_1 = require("asn1js");
const asn1_1 = require("../asn1");
const Certificate_1 = __importDefault(require("../crypto_wrappers/x509/Certificate"));
const InvalidMessageError_1 = __importDefault(require("../messages/InvalidMessageError"));
class CertificationPath {
    constructor(leafCertificate, certificateAuthorities) {
        this.leafCertificate = leafCertificate;
        this.certificateAuthorities = certificateAuthorities;
    }
    static deserialize(serialization) {
        const result = (0, asn1js_1.verifySchema)(serialization, CertificationPath.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError_1.default('Serialization did not meet structure of a CertificationPath');
        }
        const rotationBlock = result.result.CertificationPath;
        let leafCertificate;
        try {
            leafCertificate = Certificate_1.default.deserialize(rotationBlock.leafCertificate.valueBlock.valueHex);
        }
        catch (err) {
            throw new InvalidMessageError_1.default('Leaf certificate is malformed');
        }
        let certificateAuthorities;
        const casASN1 = rotationBlock.certificateAuthorities.valueBlock.value;
        const casSerialized = casASN1.map((c) => c.valueBlock.valueHex);
        try {
            certificateAuthorities = casSerialized.map((c) => Certificate_1.default.deserialize(c));
        }
        catch (err) {
            throw new InvalidMessageError_1.default('Certificate authorities contain malformed certificate');
        }
        return new CertificationPath(leafCertificate, certificateAuthorities);
    }
    serialize() {
        const casASN1 = this.certificateAuthorities.map((c) => new asn1js_1.OctetString({ valueHex: c.serialize() }));
        const sequence = (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.OctetString({ valueHex: this.leafCertificate.serialize() }), new asn1js_1.Sequence({ value: casASN1 }));
        return sequence.toBER();
    }
}
exports.CertificationPath = CertificationPath;
CertificationPath.SCHEMA = (0, asn1_1.makeHeterogeneousSequenceSchema)('CertificationPath', [
    new asn1js_1.Primitive({ name: 'leafCertificate' }),
    new asn1js_1.Constructed({ name: 'certificateAuthorities' }),
]);
//# sourceMappingURL=CertificationPath.js.map