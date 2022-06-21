import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
export function getPkijsCrypto() {
    const cryptoEngine = pkijs.getCrypto();
    if (!cryptoEngine) {
        throw new Error('PKI.js crypto engine is undefined');
    }
    return cryptoEngine;
}
export function derDeserialize(derValue) {
    const asn1Value = asn1js.fromBER(derValue);
    if (asn1Value.offset === -1) {
        throw new Error('Value is not DER-encoded');
    }
    return asn1Value.result;
}
export function generateRandom64BitValue() {
    const value = new ArrayBuffer(8);
    // @ts-ignore
    getPkijsCrypto().getRandomValues(new Uint8Array(value));
    return value;
}
//# sourceMappingURL=_utils.js.map