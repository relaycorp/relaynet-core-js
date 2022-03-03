import { BaseBlock, Constructed, DateTime, GeneralizedTime, Primitive, Sequence } from 'asn1js';
import moment from 'moment';
import { TextDecoder } from 'util';

import InvalidMessageError from './messages/InvalidMessageError';

/**
 * Create implicitly tagged SEQUENCE from the `items`.
 *
 * @param items
 */
export function makeImplicitlyTaggedSequence(...items: ReadonlyArray<BaseBlock<any>>): Sequence {
  const asn1Items = items.map((item, index) => {
    const idBlock = { tagClass: 3, tagNumber: index };
    return item instanceof Constructed
      ? new Constructed({ idBlock, value: item.valueBlock.value } as any)
      : new Primitive({ idBlock, valueHex: item.valueBlock.toBER() } as any);
  });
  return new Sequence({ value: asn1Items } as any);
}

/**
 * Serialize ASN.1 values as a DER SEQUENCE explicitly tagged.
 *
 * @param items
 */
export function derSerializeHomogeneousSequence(items: ReadonlyArray<BaseBlock<any>>): ArrayBuffer {
  const sequence = new Sequence({ value: items } as any);
  return sequence.toBER();
}

/**
 * Make a schema for a sequence whose items are all implicitly tagged.
 *
 * @param name
 * @param items
 */
export function makeHeterogeneousSequenceSchema(
  name: string,
  items: ReadonlyArray<BaseBlock<any>>,
): Sequence {
  return new Sequence({
    name,
    value: items.map((item, tagNumber) => {
      const asn1Type = item instanceof Constructed ? Constructed : Primitive;
      return new asn1Type({
        idBlock: { tagClass: 3, tagNumber },
        name: (item as any).name,
        optional: (item as any).optional ?? false,
      } as any);
    }),
  } as any);
}

export function dateToASN1DateTimeInUTC(date: Date): DateTime {
  const utcDateString = moment.utc(date).format('YYYYMMDDHHmmss');
  return new DateTime({ value: utcDateString });
}

export function asn1DateTimeToDate(dateASN1: Primitive): Date {
  const dateString = new TextDecoder().decode(dateASN1.valueBlock.valueHex) + 'Z';
  try {
    const generalizedTimeBlock = new GeneralizedTime({ value: dateString });
    return generalizedTimeBlock.toDate();
  } catch (error) {
    throw new InvalidMessageError(error as Error, 'Date is not serialized as an ASN.1 DATE-TIME');
  }
}
