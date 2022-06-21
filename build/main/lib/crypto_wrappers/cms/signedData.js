"use strict";
// tslint:disable:no-object-mutation
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
exports.verifySignature = exports.sign = exports.SignedData = void 0;
const asn1js = __importStar(require("asn1js"));
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const pkijs = __importStar(require("pkijs"));
const oids_1 = require("../../oids");
const _utils_1 = require("../_utils");
const Certificate_1 = __importDefault(require("../x509/Certificate"));
const _utils_2 = require("./_utils");
const CMSError_1 = __importDefault(require("./CMSError"));
const pkijsCrypto = (0, _utils_1.getPkijsCrypto)();
class SignedData {
    constructor(pkijsSignedData) {
        this.pkijsSignedData = pkijsSignedData;
    }
    /**
     * The signed plaintext, if it was encapsulated.
     *
     * TODO: Cache output because computation can be relatively expensive
     */
    get plaintext() {
        if (this.pkijsSignedData.encapContentInfo.eContent === undefined) {
            return null;
        }
        // ASN1.js splits the payload into 65 kib chunks, so we need to put them back together
        const contentOctetStringChunks = this.pkijsSignedData.encapContentInfo.eContent.valueBlock.value;
        const contentChunks = contentOctetStringChunks.map((os) => os.valueBlock.valueHex);
        const content = Buffer.concat(contentChunks.map((c) => new Uint8Array(c)));
        return (0, buffer_to_arraybuffer_1.default)(content);
    }
    /**
     * The signer's certificate, if it was encapsulated.
     */
    get signerCertificate() {
        if (this.pkijsSignedData.signerInfos.length === 0) {
            return null;
        }
        const signerInfo = this.pkijsSignedData.signerInfos[0];
        const matches = Array.from(this.certificates).filter((c) => c.pkijsCertificate.issuer.isEqual(signerInfo.sid.issuer) &&
            c.pkijsCertificate.serialNumber.isEqual(signerInfo.sid.serialNumber));
        return matches[0] ?? null;
    }
    /**
     * Set of encapsulated certificates.
     */
    get certificates() {
        const certificates = this.pkijsSignedData.certificates.map((c) => new Certificate_1.default(c));
        return new Set(certificates);
    }
    static async sign(plaintext, privateKey, signerCertificate, caCertificates = [], options = {}) {
        // RS-018 prohibits the use of MD5 and SHA-1, but WebCrypto doesn't support MD5
        if (options.hashingAlgorithmName === 'SHA-1') {
            throw new CMSError_1.default('SHA-1 is disallowed by RS-018');
        }
        const hashingAlgorithmName = options.hashingAlgorithmName || 'SHA-256';
        const digest = await pkijsCrypto.digest({ name: hashingAlgorithmName }, plaintext);
        const signerInfo = initSignerInfo(signerCertificate, digest);
        const encapsulatePlaintext = options.encapsulatePlaintext ?? true;
        const pkijsSignedData = new pkijs.SignedData({
            certificates: [signerCertificate, ...caCertificates].map((c) => c.pkijsCertificate),
            encapContentInfo: new pkijs.EncapsulatedContentInfo({
                eContentType: oids_1.CMS_OIDS.DATA,
                ...(encapsulatePlaintext && { eContent: new asn1js.OctetString({ valueHex: plaintext }) }),
            }),
            signerInfos: [signerInfo],
            version: 1,
        });
        await pkijsSignedData.sign(privateKey, 0, hashingAlgorithmName, encapsulatePlaintext ? undefined : plaintext);
        return SignedData.reDeserialize(pkijsSignedData);
    }
    static deserialize(signedDataSerialized) {
        const contentInfo = (0, _utils_2.deserializeContentInfo)(signedDataSerialized);
        // tslint:disable-next-line:no-let
        let pkijsSignedData;
        try {
            pkijsSignedData = new pkijs.SignedData({ schema: contentInfo.content });
        }
        catch (exc) {
            throw new CMSError_1.default('SignedData value is malformed', exc);
        }
        return new SignedData(pkijsSignedData);
    }
    /**
     *
     * @param pkijsSignedData
     * @private
     */
    static reDeserialize(pkijsSignedData) {
        const signedData = new SignedData(pkijsSignedData);
        const serialization = signedData.serialize();
        return SignedData.deserialize(serialization);
    }
    serialize() {
        const contentInfo = new pkijs.ContentInfo({
            content: this.pkijsSignedData.toSchema(true),
            contentType: oids_1.CMS_OIDS.SIGNED_DATA,
        });
        return contentInfo.toSchema().toBER(false);
    }
    async verify(expectedPlaintext) {
        const currentPlaintext = this.plaintext;
        const isPlaintextEncapsulated = currentPlaintext !== null;
        if (isPlaintextEncapsulated && expectedPlaintext !== undefined) {
            throw new CMSError_1.default('No specific plaintext should be expected because one is already encapsulated');
        }
        if (!isPlaintextEncapsulated && expectedPlaintext === undefined) {
            throw new CMSError_1.default('Plaintext should be encapsulated or explicitly set');
        }
        let verificationResult;
        try {
            verificationResult = await this.pkijsSignedData.verify({
                data: isPlaintextEncapsulated ? undefined : expectedPlaintext,
                extendedMode: true,
                signer: 0,
            });
            if (!verificationResult.signatureVerified) {
                throw verificationResult;
            }
        }
        catch (err) {
            throw new CMSError_1.default(`Invalid signature: ${err.message} (PKI.js code: ${err.code})`);
        }
    }
}
exports.SignedData = SignedData;
/**
 * Generate DER-encoded CMS SignedData signature for `plaintext`.
 *
 * TODO: REMOVE
 *
 * @param plaintext
 * @param privateKey
 * @param signerCertificate
 * @param caCertificates
 * @param options
 * @throws `CMSError` when attempting to use SHA-1 as the hashing function
 */
async function sign(plaintext, privateKey, signerCertificate, caCertificates = [], options = {}) {
    const signedData = await SignedData.sign(plaintext, privateKey, signerCertificate, caCertificates, options);
    return signedData.serialize();
}
exports.sign = sign;
function initSignerInfo(signerCertificate, digest) {
    const signerIdentifier = new pkijs.IssuerAndSerialNumber({
        issuer: signerCertificate.pkijsCertificate.issuer,
        serialNumber: signerCertificate.pkijsCertificate.serialNumber,
    });
    const contentTypeAttribute = new pkijs.Attribute({
        type: oids_1.CMS_OIDS.ATTR_CONTENT_TYPE,
        values: [new asn1js.ObjectIdentifier({ value: oids_1.CMS_OIDS.DATA })],
    });
    const digestAttribute = new pkijs.Attribute({
        type: oids_1.CMS_OIDS.ATTR_DIGEST,
        values: [new asn1js.OctetString({ valueHex: digest })],
    });
    return new pkijs.SignerInfo({
        sid: signerIdentifier,
        signedAttrs: new pkijs.SignedAndUnsignedAttributes({
            attributes: [contentTypeAttribute, digestAttribute],
            type: 0,
        }),
        version: 1,
    });
}
/**
 * Verify CMS SignedData `signature`.
 *
 * The CMS SignedData value must have the signer's certificate attached. CA certificates may
 * also be attached.
 *
 * @param cmsSignedDataSerialized The CMS SignedData signature, DER-encoded.
 * @return Signer's certificate chain, starting with the signer's certificate
 * @throws {CMSError} If `signature` could not be decoded or verified.
 *
 * TODO: Remove
 */
async function verifySignature(cmsSignedDataSerialized) {
    const signedData = SignedData.deserialize(cmsSignedDataSerialized);
    await signedData.verify();
    return {
        attachedCertificates: Array.from(signedData.certificates),
        plaintext: signedData.plaintext,
        signerCertificate: signedData.signerCertificate,
    };
}
exports.verifySignature = verifySignature;
//# sourceMappingURL=signedData.js.map