import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';
import { SubjectPublicKeyInfo } from '@peculiar/asn1-x509';

export class SessionKeySchema {
  @AsnProp({ type: AsnPropTypes.OctetString, context: 0, implicit: true })
  public keyId!: ArrayBuffer;

  @AsnProp({ type: SubjectPublicKeyInfo, context: 1, implicit: true })
  public publicKey!: SubjectPublicKeyInfo;
}
