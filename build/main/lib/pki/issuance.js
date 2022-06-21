"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.issueDeliveryAuthorization = exports.issueEndpointCertificate = exports.issueGatewayCertificate = void 0;
const keys_1 = require("../crypto_wrappers/keys");
const Certificate_1 = __importDefault(require("../crypto_wrappers/x509/Certificate"));
/**
 * Issue a Relaynet PKI certificate for a gateway.
 *
 * The issuer must be a gateway (itself or a peer).
 *
 * @param options
 */
async function issueGatewayCertificate(options) {
    const pathLenConstraint = options.issuerCertificate ? 1 : 2;
    return issueNodeCertificate({ ...options, isCA: true, pathLenConstraint });
}
exports.issueGatewayCertificate = issueGatewayCertificate;
/**
 * Issue a Relaynet PKI certificate for an endpoint.
 *
 * If the endpoint is public, it should self-issue its certificate. If it's private, its
 * certificate must be issued by its local gateway.
 *
 * @param options
 */
async function issueEndpointCertificate(options) {
    return issueNodeCertificate({ ...options, isCA: true, pathLenConstraint: 0 });
}
exports.issueEndpointCertificate = issueEndpointCertificate;
/**
 * Issue a Parcel Delivery Authorization (PDA) or Cargo Delivery Authorization (CDA).
 *
 * The issuer must be the *private* node wishing to receive messages from the subject. Both
 * nodes must be of the same type: Both gateways or both endpoints.
 *
 * @param options
 */
async function issueDeliveryAuthorization(options) {
    return issueNodeCertificate({ ...options, isCA: false, pathLenConstraint: 0 });
}
exports.issueDeliveryAuthorization = issueDeliveryAuthorization;
async function issueNodeCertificate(options) {
    const address = await computePrivateNodeAddress(options.subjectPublicKey);
    return Certificate_1.default.issue({ ...options, commonName: address });
}
async function computePrivateNodeAddress(publicKey) {
    const publicKeyDigest = Buffer.from(await (0, keys_1.getPublicKeyDigest)(publicKey));
    return `0${publicKeyDigest.toString('hex')}`;
}
//# sourceMappingURL=issuance.js.map