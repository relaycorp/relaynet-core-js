import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

import { deserializeDer } from '../_utils';

export function deserializeContentInfo(derValue: ArrayBuffer): asn1js.Sequence {
  const asn1Value = deserializeDer(derValue);
  const contentInfo = new pkijs.ContentInfo({ schema: asn1Value });
  return contentInfo.content;
}
