import * as asn1js from 'asn1js';
export declare function getPkijsCrypto(): SubtleCrypto;
export declare function derDeserialize(derValue: ArrayBuffer): asn1js.AsnType;
export declare function generateRandom64BitValue(): ArrayBuffer;
