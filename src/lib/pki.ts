import { getPublicKeyDigest } from './crypto_wrappers/keys';
import BasicCertificateIssuanceOptions from './crypto_wrappers/x509/BasicCertificateIssuanceOptions';
import Certificate from './crypto_wrappers/x509/Certificate';
import CertificateError from './crypto_wrappers/x509/CertificateError';

const MAX_DH_CERT_LENGTH_DAYS = 60;
const SECONDS_PER_DAY = 86_400;
const MAX_DH_CERT_LENGTH_MS = MAX_DH_CERT_LENGTH_DAYS * SECONDS_PER_DAY * 1_000;

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
 * Issue an initial (EC)DH certificate to initiate a channel session.
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

export class DHCertificateError extends CertificateError {}

/** Issuance options for certificate with (EC)DH subject key */
export interface DHKeyCertificateOptions extends BasicCertificateIssuanceOptions {
  readonly issuerCertificate: Certificate;
}

/**
 * Issue an initial (EC)DH certificate to initiate a channel session.
 *
 * The subject must be the node initiating the session and the issue must be the recipient of the
 * initial message.
 *
 * @param options
 */
export async function issueInitialDHKeyCertificate(
  options: DHKeyCertificateOptions,
): Promise<Certificate> {
  const startDate = options.validityStartDate || new Date();
  const certValidityLengthMs = options.validityEndDate.getTime() - startDate.getTime();
  if (MAX_DH_CERT_LENGTH_MS < certValidityLengthMs) {
    throw new DHCertificateError(
      `DH key may not be valid for more than ${MAX_DH_CERT_LENGTH_DAYS} days`,
    );
  }

  return Certificate.issue({
    ...options,
    commonName: options.issuerCertificate.getCommonName(),
    isCA: false,
    pathLenConstraint: 0,
  });
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
