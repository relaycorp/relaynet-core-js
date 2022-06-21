import { BaseBlock, DateTime, Primitive, Sequence } from 'asn1js';
/**
 * Create implicitly tagged SEQUENCE from the `items`.
 *
 * @param items
 */
export declare function makeImplicitlyTaggedSequence(...items: ReadonlyArray<BaseBlock<any>>): Sequence;
/**
 * Serialize ASN.1 values as a DER SEQUENCE explicitly tagged.
 *
 * @param items
 */
export declare function derSerializeHomogeneousSequence(items: BaseBlock<any>[]): ArrayBuffer;
/**
 * Make a schema for a sequence whose items are all implicitly tagged.
 *
 * @param name
 * @param items
 */
export declare function makeHeterogeneousSequenceSchema(name: string, items: ReadonlyArray<BaseBlock<any>>): Sequence;
export declare function dateToASN1DateTimeInUTC(date: Date): DateTime;
export declare function asn1DateTimeToDate(dateASN1: Primitive): Date;
