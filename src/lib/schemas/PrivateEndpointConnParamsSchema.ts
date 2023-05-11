import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';
import { SubjectPublicKeyInfo } from '@peculiar/asn1-x509';

import { SessionKeySchema } from './SessionKeySchema';
import { CertificationPathSchema } from './CertificationPathSchema';

export class PrivateEndpointConnParamsSchema {
  @AsnProp({ type: SubjectPublicKeyInfo, context: 0, implicit: true })
  public identityKey!: SubjectPublicKeyInfo;

  @AsnProp({ type: AsnPropTypes.VisibleString, context: 1, implicit: true })
  public internetGatewayAddress!: string;

  @AsnProp({ type: SessionKeySchema, context: 2, implicit: true })
  public sessionKey!: SessionKeySchema;

  @AsnProp({ type: CertificationPathSchema, context: 3, implicit: true })
  public deliveryAuth!: CertificationPathSchema;
}
