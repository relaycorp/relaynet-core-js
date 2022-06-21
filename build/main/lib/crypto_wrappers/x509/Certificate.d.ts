/// <reference types="node" />
import FullCertificateIssuanceOptions from './FullCertificateIssuanceOptions';
/**
 * X.509 Certificate.
 *
 * This is a high-level class on top of PKI.js Certificate, to make the use of Relaynet
 * certificates easy and safe.
 */
export default class Certificate {
    get startDate(): Date;
    get expiryDate(): Date;
    /**
     * Deserialize certificate from DER-encoded value.
     *
     * @param certDer DER-encoded X.509 certificate
     */
    static deserialize(certDer: ArrayBuffer): Certificate;
    /**
     * Issue a Relaynet PKI certificate.
     *
     * @param options
     */
    static issue(options: FullCertificateIssuanceOptions): Promise<Certificate>;
    protected privateAddressCache: string | null;
    /**
     * Serialize certificate as DER-encoded buffer.
     */
    serialize(): ArrayBuffer;
    /**
     * Return serial number.
     *
     * This doesn't return a `number` or `BigInt` because the serial number could require more than
     * 8 octets (which is the maximum number of octets required to represent a 64-bit unsigned
     * integer).
     */
    getSerialNumber(): Buffer;
    getSerialNumberHex(): string;
    getCommonName(): string;
    getPublicKey(): Promise<CryptoKey>;
    /**
     * Report whether this certificate is the same as `otherCertificate`.
     *
     * @param otherCertificate
     */
    isEqual(otherCertificate: Certificate): boolean;
    validate(): void;
    calculateSubjectPrivateAddress(): Promise<string>;
    getIssuerPrivateAddress(): string | null;
    /**
     * Return the certification path (aka "certificate chain") if this certificate can be trusted.
     *
     * @param intermediateCaCertificates The alleged chain for the certificate
     * @param trustedCertificates The collection of certificates that are actually trusted
     * @throws CertificateError when this certificate is not on a certificate path from a CA in
     *   `trustedCertificates`
     */
    getCertificationPath(intermediateCaCertificates: readonly Certificate[], trustedCertificates: readonly Certificate[]): Promise<readonly Certificate[]>;
}
