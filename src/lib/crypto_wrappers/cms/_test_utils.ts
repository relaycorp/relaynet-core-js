import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

import { derDeserialize } from '../_utils';

export function serializeContentInfo(
  content: asn1js.LocalBaseBlock,
  contentType: string,
): ArrayBuffer {
  const contentInfo = new pkijs.ContentInfo({ content, contentType });
  return contentInfo.toSchema().toBER(false);
}

export function deserializeContentInfo(contentInfoDer: ArrayBuffer): pkijs.ContentInfo {
  return new pkijs.ContentInfo({ schema: derDeserialize(contentInfoDer) });
}
