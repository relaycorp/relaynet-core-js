import { SignedData } from '../../crypto_wrappers/cms/signedData';
import { makeSafePlaintext } from './utils';
// noinspection TypeScriptAbstractClassConstructorCanBeMadeProtected
/**
 * Object to produce detached signatures given a key pair.
 */
export class Signer {
    certificate;
    privateKey;
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
        const safePlaintext = makeSafePlaintext(plaintext, this.oid);
        const signedData = await SignedData.sign(safePlaintext, this.privateKey, this.certificate, [], {
            encapsulatePlaintext: false,
        });
        return signedData.serialize();
    }
}
//# sourceMappingURL=Signer.js.map