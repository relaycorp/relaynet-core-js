import { AsnProp } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';

import { CertificateSetSchema } from './CertificateSetSchema';

export class CertificationPathSchema {
  @AsnProp({ type: Certificate, context: 0, implicit: true })
  public leaf!: Certificate;

  @AsnProp({ type: CertificateSetSchema, context: 1, implicit: true })
  public certificateAuthorities!: CertificateSetSchema;
}
