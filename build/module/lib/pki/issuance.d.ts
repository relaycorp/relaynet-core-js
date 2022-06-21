import BasicCertificateIssuanceOptions from '../crypto_wrappers/x509/BasicCertificateIssuanceOptions';
import Certificate from '../crypto_wrappers/x509/Certificate';
export interface GatewayCertificateIssuanceOptions extends BasicCertificateIssuanceOptions {
    readonly issuerCertificate?: Certificate;
}
/**
 * Issue a Relaynet PKI certificate for a gateway.
 *
 * The issuer must be a gateway (itself or a peer).
 *
 * @param options
 */
export declare function issueGatewayCertificate(options: GatewayCertificateIssuanceOptions): Promise<Certificate>;
export interface EndpointCertificateIssuanceOptions extends BasicCertificateIssuanceOptions {
    readonly issuerCertificate?: Certificate;
}
/**
 * Issue a Relaynet PKI certificate for an endpoint.
 *
 * If the endpoint is public, it should self-issue its certificate. If it's private, its
 * certificate must be issued by its local gateway.
 *
 * @param options
 */
export declare function issueEndpointCertificate(options: EndpointCertificateIssuanceOptions): Promise<Certificate>;
export interface DeliveryAuthorizationIssuanceOptions extends BasicCertificateIssuanceOptions {
    readonly issuerCertificate: Certificate;
}
/**
 * Issue a Parcel Delivery Authorization (PDA) or Cargo Delivery Authorization (CDA).
 *
 * The issuer must be the *private* node wishing to receive messages from the subject. Both
 * nodes must be of the same type: Both gateways or both endpoints.
 *
 * @param options
 */
export declare function issueDeliveryAuthorization(options: DeliveryAuthorizationIssuanceOptions): Promise<Certificate>;
