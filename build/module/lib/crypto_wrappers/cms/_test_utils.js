import * as pkijs from 'pkijs';
import { derDeserialize } from '../_utils';
export function serializeContentInfo(content, contentType) {
    const contentInfo = new pkijs.ContentInfo({ content, contentType });
    return contentInfo.toSchema().toBER(false);
}
export function deserializeContentInfo(contentInfoDer) {
    return new pkijs.ContentInfo({ schema: derDeserialize(contentInfoDer) });
}
//# sourceMappingURL=_test_utils.js.map