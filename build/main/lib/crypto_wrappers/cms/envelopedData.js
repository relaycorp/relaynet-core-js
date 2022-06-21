"use strict";
// tslint:disable:no-object-mutation max-classes-per-file
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
exports.SessionEnvelopedData = exports.SessionlessEnvelopedData = exports.EnvelopedData = void 0;
const asn1js = __importStar(require("asn1js"));
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const pkijs = __importStar(require("pkijs"));
const oids_1 = require("../../oids");
const _utils_1 = require("../_utils");
const keys_1 = require("../keys");
const _utils_2 = require("./_utils");
const CMSError_1 = __importDefault(require("./CMSError"));
const pkijsCrypto = (0, _utils_1.getPkijsCrypto)();
// CBC mode is temporary. See: https://github.com/relaycorp/relayverse/issues/16
const AES_CIPHER_MODE = 'AES-CBC';
const AES_KEY_SIZES = [128, 192, 256];
class EnvelopedData {
    /**
     * @internal
     */
    constructor(pkijsEnvelopedData) {
        this.pkijsEnvelopedData = pkijsEnvelopedData;
    }
    /**
     * Deserialize an EnvelopedData value into a `SessionlessEnvelopedData` or `SessionEnvelopedData`
     * instance.
     *
     * Depending on the type of RecipientInfo.
     *
     * @param envelopedDataSerialized
     */
    static deserialize(envelopedDataSerialized) {
        const contentInfo = (0, _utils_2.deserializeContentInfo)(envelopedDataSerialized);
        if (contentInfo.contentType !== oids_1.CMS_OIDS.ENVELOPED_DATA) {
            throw new CMSError_1.default(`ContentInfo does not wrap an EnvelopedData value (got OID ${contentInfo.contentType})`);
        }
        let pkijsEnvelopedData;
        try {
            pkijsEnvelopedData = new pkijs.EnvelopedData({ schema: contentInfo.content });
        }
        catch (error) {
            throw new CMSError_1.default(error, 'Invalid EnvelopedData value');
        }
        const recipientInfosLength = pkijsEnvelopedData.recipientInfos.length;
        if (recipientInfosLength !== 1) {
            throw new CMSError_1.default(`EnvelopedData must have exactly one RecipientInfo (got ${recipientInfosLength})`);
        }
        const recipientInfo = pkijsEnvelopedData.recipientInfos[0];
        if (![1, 2].includes(recipientInfo.variant)) {
            throw new CMSError_1.default(`Unsupported RecipientInfo (variant: ${recipientInfo.variant})`);
        }
        const envelopedDataClass = recipientInfo.variant === 1 ? SessionlessEnvelopedData : SessionEnvelopedData;
        return new envelopedDataClass(pkijsEnvelopedData);
    }
    /**
     * Return the DER serialization of the current EnvelopedData value.
     *
     * It'll be wrapped around a `ContentInfo` value.
     */
    serialize() {
        const contentInfo = new pkijs.ContentInfo({
            content: this.pkijsEnvelopedData.toSchema(),
            contentType: oids_1.CMS_OIDS.ENVELOPED_DATA,
        });
        return contentInfo.toSchema().toBER(false);
    }
    /**
     * Return the plaintext for the ciphertext contained in the current EnvelopedData value.
     *
     * @param privateKey The private key to decrypt the ciphertext.
     */
    async decrypt(privateKey) {
        const privateKeyDer = await (0, keys_1.derSerializePrivateKey)(privateKey);
        try {
            return await this.pkijsEnvelopedData.decrypt(0, {
                recipientPrivateKey: (0, buffer_to_arraybuffer_1.default)(privateKeyDer),
            });
        }
        catch (error) {
            throw new CMSError_1.default(error, 'Decryption failed');
        }
    }
}
exports.EnvelopedData = EnvelopedData;
/**
 * CMS EnvelopedData representation that doesn't use the Channel Session Protocol.
 *
 * Consequently, it uses the key transport choice (`KeyTransRecipientInfo`) from CMS.
 */
class SessionlessEnvelopedData extends EnvelopedData {
    /**
     * Return an EnvelopedData value without using the Channel Session Protocol.
     *
     * @param plaintext The plaintext whose ciphertext has to be embedded in the EnvelopedData value.
     * @param certificate The certificate for the recipient.
     * @param options Any encryption options.
     */
    static async encrypt(plaintext, certificate, options = {}) {
        const pkijsEnvelopedData = new pkijs.EnvelopedData();
        pkijsEnvelopedData.addRecipientByCertificate(certificate.pkijsCertificate, { oaepHashAlgorithm: 'SHA-256' }, 1);
        const aesKeySize = getAesKeySize(options.aesKeySize);
        await pkijsEnvelopedData.encrypt({ name: AES_CIPHER_MODE, length: aesKeySize }, plaintext);
        return new SessionlessEnvelopedData(pkijsEnvelopedData);
    }
    getRecipientKeyId() {
        const recipientInfo = this.pkijsEnvelopedData.recipientInfos[0].value;
        (0, _utils_2.assertPkiType)(recipientInfo, pkijs.KeyTransRecipientInfo, 'recipientInfo');
        (0, _utils_2.assertPkiType)(recipientInfo.rid, pkijs.IssuerAndSerialNumber, 'recipientInfo.rid');
        const serialNumberBlock = recipientInfo.rid.serialNumber;
        return Buffer.from(serialNumberBlock.valueBlock.valueHexView);
    }
}
exports.SessionlessEnvelopedData = SessionlessEnvelopedData;
function getAesKeySize(aesKeySize) {
    if (aesKeySize && !AES_KEY_SIZES.includes(aesKeySize)) {
        throw new CMSError_1.default(`Invalid AES key size (${aesKeySize})`);
    }
    return aesKeySize || 128;
}
/**
 * CMS EnvelopedData representation using the Channel Session Protocol.
 *
 * Consequently, it uses the key agreement (`KeyAgreeRecipientInfo`) from CMS.
 */
class SessionEnvelopedData extends EnvelopedData {
    /**
     * Return an EnvelopedData value using the Channel Session Protocol.
     *
     * @param plaintext The plaintext whose ciphertext has to be embedded in the EnvelopedData value.
     * @param recipientSessionKey The ECDH public key of the recipient.
     * @param options Any encryption options.
     */
    static async encrypt(plaintext, recipientSessionKey, options = {}) {
        // Generate id for generated (EC)DH key and attach it to unprotectedAttrs per RS-003:
        const dhKeyId = (0, _utils_1.generateRandom64BitValue)();
        const dhKeyIdAttribute = new pkijs.Attribute({
            type: oids_1.RELAYNET_OIDS.ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
            values: [new asn1js.OctetString({ valueHex: dhKeyId })],
        });
        const pkijsEnvelopedData = new pkijs.EnvelopedData({
            unprotectedAttrs: [dhKeyIdAttribute],
        });
        pkijsEnvelopedData.addRecipientByKeyIdentifier(recipientSessionKey.publicKey, recipientSessionKey.keyId);
        const aesKeySize = getAesKeySize(options.aesKeySize);
        const [pkijsEncryptionResult] = await pkijsEnvelopedData.encrypt({ name: AES_CIPHER_MODE, length: aesKeySize }, plaintext);
        (0, _utils_2.assertUndefined)(pkijsEncryptionResult, 'pkijsEncryptionResult');
        const dhPrivateKey = pkijsEncryptionResult.ecdhPrivateKey;
        const envelopedData = new SessionEnvelopedData(pkijsEnvelopedData);
        return { dhPrivateKey, dhKeyId, envelopedData };
    }
    /**
     * Return the key of the ECDH key of the originator/producer of the EnvelopedData value.
     */
    async getOriginatorKey() {
        const keyId = extractOriginatorKeyId(this.pkijsEnvelopedData);
        const recipientInfo = this.pkijsEnvelopedData.recipientInfos[0];
        if (recipientInfo.variant !== 2) {
            throw new CMSError_1.default(`Expected KeyAgreeRecipientInfo (got variant: ${recipientInfo.variant})`);
        }
        (0, _utils_2.assertPkiType)(recipientInfo.value, pkijs.KeyAgreeRecipientInfo, 'recipientInfo.value');
        const originator = recipientInfo.value.originator.value;
        const publicKeyDer = originator.toSchema().toBER(false);
        const curveOid = originator.algorithm.algorithmParams.valueBlock.toString();
        // @ts-ignore
        const curveParams = pkijsCrypto.getAlgorithmByOID(curveOid);
        const publicKey = await (0, keys_1.derDeserializeECDHPublicKey)(Buffer.from(publicKeyDer), curveParams.name);
        return { keyId, publicKey };
    }
    getRecipientKeyId() {
        const keyInfo = this.pkijsEnvelopedData.recipientInfos[0].value;
        (0, _utils_2.assertPkiType)(keyInfo, pkijs.KeyAgreeRecipientInfo, 'keyInfo');
        const encryptedKey = keyInfo.recipientEncryptedKeys.encryptedKeys[0];
        const subjectKeyIdentifierBlock = encryptedKey.rid.value.subjectKeyIdentifier;
        return Buffer.from(subjectKeyIdentifierBlock.valueBlock.valueHex);
    }
}
exports.SessionEnvelopedData = SessionEnvelopedData;
function extractOriginatorKeyId(envelopedData) {
    const unprotectedAttrs = envelopedData.unprotectedAttrs || [];
    if (unprotectedAttrs.length === 0) {
        throw new CMSError_1.default('unprotectedAttrs must be present when using channel session');
    }
    const matchingAttrs = unprotectedAttrs.filter((a) => a.type === oids_1.RELAYNET_OIDS.ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER);
    if (matchingAttrs.length === 0) {
        throw new CMSError_1.default('unprotectedAttrs does not contain originator key id');
    }
    const originatorKeyIdAttr = matchingAttrs[0];
    // @ts-ignore
    const originatorKeyIds = originatorKeyIdAttr.values;
    if (originatorKeyIds.length !== 1) {
        throw new CMSError_1.default(`Originator key id attribute must have exactly one value (got ${originatorKeyIds.length})`);
    }
    const serialNumberBlock = originatorKeyIds[0];
    return Buffer.from(serialNumberBlock.valueBlock.valueHex);
}
//# sourceMappingURL=envelopedData.js.map