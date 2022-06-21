"use strict";
// tslint:disable:max-classes-per-file
Object.defineProperty(exports, "__esModule", { value: true });
exports.Verifier = void 0;
const signedData_1 = require("../../crypto_wrappers/cms/signedData");
const utils_1 = require("./utils");
// noinspection TypeScriptAbstractClassConstructorCanBeMadeProtected
/**
 * Object to verify detached signatures given a key pair.
 */
class Verifier {
    constructor(trustedCertificates) {
        this.trustedCertificates = trustedCertificates;
    }
    /**
     * Verify `signatureSerialized` and return the signer's certificate if valid.
     *
     * @param signatureSerialized
     * @param expectedPlaintext
     * @throws CMSError if the signatureSerialized is invalid
     * @throws CertificateError if the signer isn't trusted
     */
    async verify(signatureSerialized, expectedPlaintext) {
        const signedData = signedData_1.SignedData.deserialize(signatureSerialized);
        const safePlaintext = (0, utils_1.makeSafePlaintext)(expectedPlaintext, this.oid);
        await signedData.verify(safePlaintext);
        const signerCertificate = signedData.signerCertificate;
        await signerCertificate.getCertificationPath([], this.trustedCertificates);
        return signerCertificate;
    }
}
exports.Verifier = Verifier;
//# sourceMappingURL=Verifier.js.map