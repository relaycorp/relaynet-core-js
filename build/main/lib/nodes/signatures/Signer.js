"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Signer = void 0;
const signedData_1 = require("../../crypto_wrappers/cms/signedData");
const utils_1 = require("./utils");
// noinspection TypeScriptAbstractClassConstructorCanBeMadeProtected
/**
 * Object to produce detached signatures given a key pair.
 */
class Signer {
    /**
     *
     * @param certificate The certificate of the node
     * @param privateKey The private key of the node
     */
    constructor(certificate, privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }
    async sign(plaintext) {
        const safePlaintext = (0, utils_1.makeSafePlaintext)(plaintext, this.oid);
        const signedData = await signedData_1.SignedData.sign(safePlaintext, this.privateKey, this.certificate, [], {
            encapsulatePlaintext: false,
        });
        return signedData.serialize();
    }
}
exports.Signer = Signer;
//# sourceMappingURL=Signer.js.map