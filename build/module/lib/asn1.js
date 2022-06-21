import { Constructed, DateTime, GeneralizedTime, Primitive, Sequence } from 'asn1js';
import moment from 'moment';
import { TextDecoder } from 'util';
import InvalidMessageError from './messages/InvalidMessageError';
/**
 * Create implicitly tagged SEQUENCE from the `items`.
 *
 * @param items
 */
export function makeImplicitlyTaggedSequence(...items) {
    const asn1Items = items.map((item, index) => {
        const idBlock = { tagClass: 3, tagNumber: index };
        return item instanceof Constructed
            ? new Constructed({ idBlock, value: item.valueBlock.value })
            : new Primitive({ idBlock, valueHex: item.valueBlock.toBER() });
    });
    return new Sequence({ value: asn1Items });
}
/**
 * Serialize ASN.1 values as a DER SEQUENCE explicitly tagged.
 *
 * @param items
 */
// tslint:disable-next-line:readonly-array
export function derSerializeHomogeneousSequence(items) {
    const sequence = new Sequence({ value: items });
    return sequence.toBER();
}
/**
 * Make a schema for a sequence whose items are all implicitly tagged.
 *
 * @param name
 * @param items
 */
export function makeHeterogeneousSequenceSchema(name, items) {
    return new Sequence({
        name,
        value: items.map((item, tagNumber) => {
            const asn1Type = item instanceof Constructed ? Constructed : Primitive;
            return new asn1Type({
                idBlock: { tagClass: 3, tagNumber },
                name: item.name,
                optional: item.optional,
            });
        }),
    });
}
export function dateToASN1DateTimeInUTC(date) {
    const utcDateString = moment.utc(date).format('YYYYMMDDHHmmss');
    return new DateTime({ value: utcDateString });
}
export function asn1DateTimeToDate(dateASN1) {
    const dateString = new TextDecoder().decode(dateASN1.valueBlock.valueHex) + 'Z';
    try {
        const generalizedTimeBlock = new GeneralizedTime({ value: dateString });
        return generalizedTimeBlock.toDate();
    }
    catch (error) {
        throw new InvalidMessageError(error, 'Date is not serialized as an ASN.1 DATE-TIME');
    }
}
//# sourceMappingURL=asn1.js.map