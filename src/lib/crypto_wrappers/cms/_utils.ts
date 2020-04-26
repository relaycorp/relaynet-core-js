import * as pkijs from 'pkijs';

import { derDeserialize } from '../_utils';
import CMSError from './CMSError';

export function deserializeContentInfo(derValue: ArrayBuffer): pkijs.ContentInfo {
  try {
    const asn1Value = derDeserialize(derValue);
    return new pkijs.ContentInfo({ schema: asn1Value });
  } catch (error) {
    throw new CMSError(error, 'Could not deserialize CMS ContentInfo');
  }
}
