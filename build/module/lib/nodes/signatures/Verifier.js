// tslint:disable:max-classes-per-file
import { SignedData } from '../../crypto_wrappers/cms/signedData';
import { makeSafePlaintext } from './utils';
// noinspection TypeScriptAbstractClassConstructorCanBeMadeProtected
/**
 * Object to verify detached signatures given a key pair.
 */
export class Verifier {
    trustedCertificates;
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
        const signedData = SignedData.deserialize(signatureSerialized);
        const safePlaintext = makeSafePlaintext(expectedPlaintext, this.oid);
        await signedData.verify(safePlaintext);
        const signerCertificate = signedData.signerCertificate;
        await signerCertificate.getCertificationPath([], this.trustedCertificates);
        return signerCertificate;
    }
}
//# sourceMappingURL=Verifier.js.map