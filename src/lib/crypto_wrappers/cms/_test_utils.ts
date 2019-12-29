import * as pkijs from 'pkijs';
import { deserializeDer } from '../_utils';

export function deserializeContentInfo(contentInfoDer: ArrayBuffer): pkijs.ContentInfo {
  return new pkijs.ContentInfo({ schema: deserializeDer(contentInfoDer) });
}
