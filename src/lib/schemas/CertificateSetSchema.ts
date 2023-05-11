import { AsnArray, AsnType, AsnTypeTypes } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';

@AsnType({ type: AsnTypeTypes.Set, itemType: Certificate })
export class CertificateSetSchema extends AsnArray<Certificate> {}
