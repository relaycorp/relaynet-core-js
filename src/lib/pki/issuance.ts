import { getPublicKeyDigest } from '../crypto_wrappers/keys';
import BasicCertificateIssuanceOptions from '../crypto_wrappers/x509/BasicCertificateIssuanceOptions';
import Certificate from '../crypto_wrappers/x509/Certificate';

export interface GatewayCertificateIssuanceOptions extends BasicCertificateIssuanceOptions {
  readonly issuerCertificate?: Certificate; // Absent/self-issued when gateway is public
}

/**
 * Issue a Relaynet PKI certificate for a gateway.
 *
 * The issuer must be a gateway (itself or a peer).
 *
 * @param options
 */
export async function issueGatewayCertificate(
  options: GatewayCertificateIssuanceOptions,
): Promise<Certificate> {
  const pathLenConstraint = options.issuerCertificate ? 1 : 2;
  return issueNodeCertificate({ ...options, isCA: true, pathLenConstraint });
}

export interface EndpointCertificateIssuanceOptions extends BasicCertificateIssuanceOptions {
  readonly issuerCertificate?: Certificate; // Absent/self-issued when endpoint is public
}

/**
 * Issue a Relaynet PKI certificate for an endpoint.
 *
 * If the endpoint is public, it should self-issue its certificate. If it's private, its
 * certificate must be issued by its local gateway.
 *
 * @param options
 */
export async function issueEndpointCertificate(
  options: EndpointCertificateIssuanceOptions,
): Promise<Certificate> {
  return issueNodeCertificate({ ...options, isCA: true, pathLenConstraint: 0 });
}

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
export async function issueDeliveryAuthorization(
  options: DeliveryAuthorizationIssuanceOptions,
): Promise<Certificate> {
  return issueNodeCertificate({ ...options, isCA: false, pathLenConstraint: 0 });
}

interface NodeCertificateOptions extends BasicCertificateIssuanceOptions {
  readonly isCA: boolean;
  readonly pathLenConstraint: number;
}

async function issueNodeCertificate(options: NodeCertificateOptions): Promise<Certificate> {
  const address = await computePrivateNodeAddress(options.subjectPublicKey);
  return Certificate.issue({ ...options, commonName: address });
}

async function computePrivateNodeAddress(publicKey: CryptoKey): Promise<string> {
  const publicKeyDigest = Buffer.from(await getPublicKeyDigest(publicKey));
  return `0${publicKeyDigest.toString('hex')}`;
}
