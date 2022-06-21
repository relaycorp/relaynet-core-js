"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const asn1js_1 = require("asn1js");
const moment_1 = __importDefault(require("moment"));
const util_1 = require("util");
const _test_utils_1 = require("./_test_utils");
const asn1_1 = require("./asn1");
const _utils_1 = require("./crypto_wrappers/_utils");
const InvalidMessageError_1 = __importDefault(require("./messages/InvalidMessageError"));
describe('makeImplicitlyTaggedSequence', () => {
    test('An empty input should result in an empty sequence', () => {
        const sequence = (0, asn1_1.makeImplicitlyTaggedSequence)();
        expect(sequence.valueBlock.value).toHaveLength(0);
    });
    test('Primitive values should be implicitly tagged', () => {
        const originalItem = new asn1js_1.OctetString({ valueHex: (0, _test_utils_1.arrayBufferFrom)('foo') });
        const sequence = (0, asn1_1.makeImplicitlyTaggedSequence)(originalItem);
        expectItemToBeImplicitlyTaggedPrimitive(sequence.valueBlock.value[0], originalItem, 0);
    });
    test('Constructed items should be implicitly tagged', () => {
        const originalSubItem1 = new asn1js_1.VisibleString({ value: 'foo' });
        const originalSubItem2 = new asn1js_1.VisibleString({ value: 'bar' });
        const originalItem = new asn1js_1.Sequence({ value: [originalSubItem1, originalSubItem2] });
        const sequence = (0, asn1_1.makeImplicitlyTaggedSequence)(originalItem);
        const sequenceItem = sequence.valueBlock.value[0];
        expect(sequenceItem).toBeInstanceOf(asn1js_1.Constructed);
        expect(sequenceItem.idBlock).toEqual(expect.objectContaining({ tagClass: 3, tagNumber: 0 }));
        expect(sequenceItem.valueBlock.value[0]).toBe(originalSubItem1);
        expect(sequenceItem.valueBlock.value[1]).toBe(originalSubItem2);
    });
    test('Multiple values should be implicitly tagged', () => {
        const originalItem1 = new asn1js_1.VisibleString({ value: 'foo' });
        const originalItem2 = new asn1js_1.OctetString({ valueHex: (0, _test_utils_1.arrayBufferFrom)('bar') });
        const sequence = (0, asn1_1.makeImplicitlyTaggedSequence)(originalItem1, originalItem2);
        expectItemToBeImplicitlyTaggedPrimitive(sequence.valueBlock.value[0], originalItem1, 0);
        expectItemToBeImplicitlyTaggedPrimitive(sequence.valueBlock.value[1], originalItem2, 1);
    });
    function expectItemToBeImplicitlyTaggedPrimitive(item, itemExplicitlyTagged, expectedTagNumber) {
        if (item instanceof asn1js_1.Primitive) {
            expect.fail('Item is not a primitive');
        }
        const itemTyped = item;
        expect(itemTyped.idBlock).toEqual(expect.objectContaining({ tagClass: 3, tagNumber: expectedTagNumber }));
        expect(itemTyped.valueBlock.valueHex).toEqual(itemExplicitlyTagged.valueBlock.valueHex);
    }
});
describe('derSerializeHomogeneousSequence', () => {
    test('An empty input should result in an empty sequence', () => {
        const serialization = (0, asn1_1.derSerializeHomogeneousSequence)([]);
        const deserialization = (0, _utils_1.derDeserialize)(serialization);
        expect(deserialization.valueBlock.value).toHaveLength(0);
    });
    test('Values should be explicitly tagged', () => {
        const item1 = new asn1js_1.VisibleString({ value: 'foo' });
        const item2 = new asn1js_1.OctetString({ valueHex: (0, _test_utils_1.arrayBufferFrom)('bar') });
        const serialization = (0, asn1_1.derSerializeHomogeneousSequence)([item1, item2]);
        const deserialization = (0, _utils_1.derDeserialize)(serialization);
        expect(deserialization.valueBlock.value).toHaveLength(2);
        (0, _test_utils_1.expectArrayBuffersToEqual)(item1.toBER(), deserialization.valueBlock.value[0].toBER());
        (0, _test_utils_1.expectArrayBuffersToEqual)(item2.toBER(), deserialization.valueBlock.value[1].toBER());
    });
});
describe('makeHeterogeneousSequenceSchema', () => {
    const EMPTY_SEQUENCE_SERIALIZED = new asn1js_1.Sequence().toBER();
    const PRIMITIVE_ITEM = new asn1js_1.Primitive({ valueHex: (0, _test_utils_1.arrayBufferFrom)('primitive') });
    const SINGLE_ITEM_SEQUENCE_SERIALIZED = (0, asn1_1.makeImplicitlyTaggedSequence)(PRIMITIVE_ITEM).toBER();
    test('Schema name should be honored', () => {
        const schemaName = 'Foo';
        const schema = (0, asn1_1.makeHeterogeneousSequenceSchema)(schemaName, []);
        expect(schema).toHaveProperty('name', schemaName);
    });
    test('Primitive values should remain as such', () => {
        const item = new asn1js_1.Primitive({ name: 'item' });
        const schema = (0, asn1_1.makeHeterogeneousSequenceSchema)('Foo', [item]);
        expect(schema.valueBlock.value).toHaveLength(1);
        expect(schema.valueBlock.value[0]).toBeInstanceOf(asn1js_1.Primitive);
    });
    test('Constructed items should remain as such', () => {
        const item = new asn1js_1.Constructed({ name: 'item' });
        const schema = (0, asn1_1.makeHeterogeneousSequenceSchema)('Foo', [item]);
        expect(schema.valueBlock.value).toHaveLength(1);
        expect(schema.valueBlock.value[0]).toBeInstanceOf(asn1js_1.Constructed);
    });
    test('Items should be implicitly tagged', () => {
        const item1 = new asn1js_1.Primitive({ name: 'item1' });
        const item2 = new asn1js_1.Constructed({ name: 'item2' });
        const schema = (0, asn1_1.makeHeterogeneousSequenceSchema)('Foo', [item1, item2]);
        expect(schema.valueBlock.value).toHaveLength(2);
        expect(schema.valueBlock.value[0]).toHaveProperty('idBlock', expect.objectContaining({ tagClass: 3, tagNumber: 0 }));
        expect(schema.valueBlock.value[1]).toHaveProperty('idBlock', expect.objectContaining({ tagClass: 3, tagNumber: 1 }));
    });
    test('Item names should be honored', () => {
        const item = new asn1js_1.Primitive({ name: 'item' });
        const schema = (0, asn1_1.makeHeterogeneousSequenceSchema)('Foo', [item]);
        expect(schema.valueBlock.value[0]).toHaveProperty('name', item.name);
    });
    test('Optional items should remain as such', () => {
        const item = new asn1js_1.Primitive({ name: 'item', optional: true });
        const schema = (0, asn1_1.makeHeterogeneousSequenceSchema)('Foo', [item]);
        expect((0, asn1js_1.verifySchema)(EMPTY_SEQUENCE_SERIALIZED, schema)).toHaveProperty('verified', true);
        expect((0, asn1js_1.verifySchema)(SINGLE_ITEM_SEQUENCE_SERIALIZED, schema)).toHaveProperty('verified', true);
    });
    test('Required items should remain as such', () => {
        const item = new asn1js_1.Primitive({ name: 'item', optional: false });
        const schema = (0, asn1_1.makeHeterogeneousSequenceSchema)('Foo', [item]);
        expect((0, asn1js_1.verifySchema)(EMPTY_SEQUENCE_SERIALIZED, schema)).toHaveProperty('verified', false);
        expect((0, asn1js_1.verifySchema)(SINGLE_ITEM_SEQUENCE_SERIALIZED, schema)).toHaveProperty('verified', true);
    });
    test('Items should be required by default', () => {
        const item = new asn1js_1.Primitive({ name: 'item' });
        const schema = (0, asn1_1.makeHeterogeneousSequenceSchema)('Foo', [item]);
        expect((0, asn1js_1.verifySchema)(EMPTY_SEQUENCE_SERIALIZED, schema)).toHaveProperty('verified', false);
        expect((0, asn1js_1.verifySchema)(SINGLE_ITEM_SEQUENCE_SERIALIZED, schema)).toHaveProperty('verified', true);
    });
});
describe('dateToASN1DateTimeInUTC', () => {
    const textDecoder = new util_1.TextDecoder();
    test('Date should be serialized with UTC and second-level precision', () => {
        const nonUtcDate = new Date('01 Jan 2019 12:00:00 GMT+11:00');
        const datetimeBlock = (0, asn1_1.dateToASN1DateTimeInUTC)(nonUtcDate);
        expect(textDecoder.decode(datetimeBlock.valueBlock.valueHex)).toEqual('20190101010000');
    });
    test('Date should lose millisecond precision', () => {
        const nonUtcDate = new Date('01 Jan 2019 12:00:00.345 GMT+11:00');
        const datetimeBlock = (0, asn1_1.dateToASN1DateTimeInUTC)(nonUtcDate);
        expect(textDecoder.decode(datetimeBlock.valueBlock.valueHex)).toEqual('20190101010000');
    });
});
describe('asn1DateTimeToDate', () => {
    const NOW = new Date();
    NOW.setMilliseconds(0);
    test('Date with second-level precision should be accepted', async () => {
        const dateTimeASN1 = (0, asn1_1.dateToASN1DateTimeInUTC)(NOW);
        const datePrimitive = new asn1js_1.Primitive({
            idBlock: { tagClass: 3, tagNumber: 0 },
            valueHex: dateTimeASN1.valueBlock.toBER(),
        });
        const dateDeserialized = (0, asn1_1.asn1DateTimeToDate)(datePrimitive);
        expect(dateDeserialized).toEqual(NOW);
    });
    test('Date with date-level precision should be accepted', async () => {
        const dateString = moment_1.default.utc(NOW).format('YYYYMMDD');
        const datePrimitive = new asn1js_1.Primitive({
            idBlock: { tagClass: 3, tagNumber: 0 },
            valueHex: (0, _test_utils_1.arrayBufferFrom)(dateString),
        });
        const dateDeserialized = (0, asn1_1.asn1DateTimeToDate)(datePrimitive);
        const expectedDate = new Date(moment_1.default.utc(NOW).format('YYYY-MM-DD'));
        expect(dateDeserialized).toEqual(expectedDate);
    });
    test('Date not serialized as an ASN.1 DATE-TIME should be refused', async () => {
        const invalidDateTimeASN1 = new asn1js_1.Primitive({
            idBlock: { tagClass: 3, tagNumber: 0 },
            valueHex: (0, _test_utils_1.arrayBufferFrom)('invalid date'),
        });
        expect(() => (0, asn1_1.asn1DateTimeToDate)(invalidDateTimeASN1)).toThrowWithMessage(InvalidMessageError_1.default, /^Date is not serialized as an ASN.1 DATE-TIME/);
    });
});
//# sourceMappingURL=asn1.spec.js.map