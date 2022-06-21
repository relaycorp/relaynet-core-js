/**
 * Plain RSA signatures are used when CMS SignedData can't be used. That is, when the signer
 * doesn't (yet) have a certificate.
 */
import * as utils from './_utils';
const rsaPssParams = {
    hash: { name: 'SHA-256' },
    name: 'RSA-PSS',
    saltLength: 32,
};
const pkijsCrypto = utils.getPkijsCrypto();
export async function sign(plaintext, privateKey) {
    return pkijsCrypto.sign(rsaPssParams, privateKey, plaintext);
}
export async function verify(signature, publicKey, expectedPlaintext) {
    return pkijsCrypto.verify(rsaPssParams, publicKey, signature, expectedPlaintext);
}
//# sourceMappingURL=rsaSigning.js.map