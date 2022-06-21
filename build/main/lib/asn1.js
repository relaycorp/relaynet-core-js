"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.asn1DateTimeToDate = exports.dateToASN1DateTimeInUTC = exports.makeHeterogeneousSequenceSchema = exports.derSerializeHomogeneousSequence = exports.makeImplicitlyTaggedSequence = void 0;
const asn1js_1 = require("asn1js");
const moment_1 = __importDefault(require("moment"));
const util_1 = require("util");
const InvalidMessageError_1 = __importDefault(require("./messages/InvalidMessageError"));
/**
 * Create implicitly tagged SEQUENCE from the `items`.
 *
 * @param items
 */
function makeImplicitlyTaggedSequence(...items) {
    const asn1Items = items.map((item, index) => {
        const idBlock = { tagClass: 3, tagNumber: index };
        return item instanceof asn1js_1.Constructed
            ? new asn1js_1.Constructed({ idBlock, value: item.valueBlock.value })
            : new asn1js_1.Primitive({ idBlock, valueHex: item.valueBlock.toBER() });
    });
    return new asn1js_1.Sequence({ value: asn1Items });
}
exports.makeImplicitlyTaggedSequence = makeImplicitlyTaggedSequence;
/**
 * Serialize ASN.1 values as a DER SEQUENCE explicitly tagged.
 *
 * @param items
 */
// tslint:disable-next-line:readonly-array
function derSerializeHomogeneousSequence(items) {
    const sequence = new asn1js_1.Sequence({ value: items });
    return sequence.toBER();
}
exports.derSerializeHomogeneousSequence = derSerializeHomogeneousSequence;
/**
 * Make a schema for a sequence whose items are all implicitly tagged.
 *
 * @param name
 * @param items
 */
function makeHeterogeneousSequenceSchema(name, items) {
    return new asn1js_1.Sequence({
        name,
        value: items.map((item, tagNumber) => {
            const asn1Type = item instanceof asn1js_1.Constructed ? asn1js_1.Constructed : asn1js_1.Primitive;
            return new asn1Type({
                idBlock: { tagClass: 3, tagNumber },
                name: item.name,
                optional: item.optional,
            });
        }),
    });
}
exports.makeHeterogeneousSequenceSchema = makeHeterogeneousSequenceSchema;
function dateToASN1DateTimeInUTC(date) {
    const utcDateString = moment_1.default.utc(date).format('YYYYMMDDHHmmss');
    return new asn1js_1.DateTime({ value: utcDateString });
}
exports.dateToASN1DateTimeInUTC = dateToASN1DateTimeInUTC;
function asn1DateTimeToDate(dateASN1) {
    const dateString = new util_1.TextDecoder().decode(dateASN1.valueBlock.valueHex) + 'Z';
    try {
        const generalizedTimeBlock = new asn1js_1.GeneralizedTime({ value: dateString });
        return generalizedTimeBlock.toDate();
    }
    catch (error) {
        throw new InvalidMessageError_1.default(error, 'Date is not serialized as an ASN.1 DATE-TIME');
    }
}
exports.asn1DateTimeToDate = asn1DateTimeToDate;
//# sourceMappingURL=asn1.js.map