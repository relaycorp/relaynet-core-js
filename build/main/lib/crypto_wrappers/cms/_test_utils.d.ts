import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
export declare function serializeContentInfo(content: asn1js.BaseBlock<any>, contentType: string): ArrayBuffer;
export declare function deserializeContentInfo(contentInfoDer: ArrayBuffer): pkijs.ContentInfo;
