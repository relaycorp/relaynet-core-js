import { BaseBlock, DateTime, GeneralizedTime, Primitive, Sequence } from 'asn1js';
import moment from 'moment';
import { TextDecoder } from 'util';

import InvalidMessageError from './messages/InvalidMessageError';

export function serializeSequence(...items: ReadonlyArray<BaseBlock<any>>): ArrayBuffer {
  const asn1Items = items.map(
    (item, index) =>
      new Primitive({
        idBlock: { tagClass: 3, tagNumber: index },
        valueHex: item.valueBlock.toBER(),
      } as any),
  );
  return new Sequence({ value: asn1Items } as any).toBER(false);
}

/**
 * Make a schema for a sequence whose items are all implicitly tagged.
 *
 * @param name
 * @param itemNames
 */
export function makeSequenceSchema(name: string, itemNames: readonly string[]): Sequence {
  return new Sequence({
    name,
    value: itemNames.map(
      (itemName, tagNumber) =>
        new Primitive({
          idBlock: { tagClass: 3, tagNumber },
          name: itemName,
          optional: false,
        } as any),
    ),
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
    throw new InvalidMessageError(error, 'Date is not serialized as an ASN.1 DATE-TIME');
  }
}
