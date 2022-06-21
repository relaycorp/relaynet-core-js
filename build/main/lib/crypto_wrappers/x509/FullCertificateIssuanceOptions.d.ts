import BasicCertificateIssuanceOptions from './BasicCertificateIssuanceOptions';
import Certificate from './Certificate';
export default interface FullCertificateIssuanceOptions extends BasicCertificateIssuanceOptions {
    readonly isCA?: boolean;
    readonly commonName: string;
    readonly issuerCertificate?: Certificate;
    readonly pathLenConstraint?: number;
}
