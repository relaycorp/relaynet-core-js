import { getPublicKeyDigest } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
/**
 * Issue a Relaynet PKI certificate for a gateway.
 *
 * The issuer must be a gateway (itself or a peer).
 *
 * @param options
 */
export async function issueGatewayCertificate(options) {
    const pathLenConstraint = options.issuerCertificate ? 1 : 2;
    return issueNodeCertificate({ ...options, isCA: true, pathLenConstraint });
}
/**
 * Issue a Relaynet PKI certificate for an endpoint.
 *
 * If the endpoint is public, it should self-issue its certificate. If it's private, its
 * certificate must be issued by its local gateway.
 *
 * @param options
 */
export async function issueEndpointCertificate(options) {
    return issueNodeCertificate({ ...options, isCA: true, pathLenConstraint: 0 });
}
/**
 * Issue a Parcel Delivery Authorization (PDA) or Cargo Delivery Authorization (CDA).
 *
 * The issuer must be the *private* node wishing to receive messages from the subject. Both
 * nodes must be of the same type: Both gateways or both endpoints.
 *
 * @param options
 */
export async function issueDeliveryAuthorization(options) {
    return issueNodeCertificate({ ...options, isCA: false, pathLenConstraint: 0 });
}
async function issueNodeCertificate(options) {
    const address = await computePrivateNodeAddress(options.subjectPublicKey);
    return Certificate.issue({ ...options, commonName: address });
}
async function computePrivateNodeAddress(publicKey) {
    const publicKeyDigest = Buffer.from(await getPublicKeyDigest(publicKey));
    return `0${publicKeyDigest.toString('hex')}`;
}
//# sourceMappingURL=issuance.js.map