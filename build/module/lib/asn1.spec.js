import { Constructed, OctetString, Primitive, Sequence, verifySchema, VisibleString, } from 'asn1js';
import moment from 'moment';
import { TextDecoder } from 'util';
import { arrayBufferFrom, expectArrayBuffersToEqual } from './_test_utils';
import { asn1DateTimeToDate, dateToASN1DateTimeInUTC, derSerializeHomogeneousSequence, makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence, } from './asn1';
import { derDeserialize } from './crypto_wrappers/_utils';
import InvalidMessageError from './messages/InvalidMessageError';
describe('makeImplicitlyTaggedSequence', () => {
    test('An empty input should result in an empty sequence', () => {
        const sequence = makeImplicitlyTaggedSequence();
        expect(sequence.valueBlock.value).toHaveLength(0);
    });
    test('Primitive values should be implicitly tagged', () => {
        const originalItem = new OctetString({ valueHex: arrayBufferFrom('foo') });
        const sequence = makeImplicitlyTaggedSequence(originalItem);
        expectItemToBeImplicitlyTaggedPrimitive(sequence.valueBlock.value[0], originalItem, 0);
    });
    test('Constructed items should be implicitly tagged', () => {
        const originalSubItem1 = new VisibleString({ value: 'foo' });
        const originalSubItem2 = new VisibleString({ value: 'bar' });
        const originalItem = new Sequence({ value: [originalSubItem1, originalSubItem2] });
        const sequence = makeImplicitlyTaggedSequence(originalItem);
        const sequenceItem = sequence.valueBlock.value[0];
        expect(sequenceItem).toBeInstanceOf(Constructed);
        expect(sequenceItem.idBlock).toEqual(expect.objectContaining({ tagClass: 3, tagNumber: 0 }));
        expect(sequenceItem.valueBlock.value[0]).toBe(originalSubItem1);
        expect(sequenceItem.valueBlock.value[1]).toBe(originalSubItem2);
    });
    test('Multiple values should be implicitly tagged', () => {
        const originalItem1 = new VisibleString({ value: 'foo' });
        const originalItem2 = new OctetString({ valueHex: arrayBufferFrom('bar') });
        const sequence = makeImplicitlyTaggedSequence(originalItem1, originalItem2);
        expectItemToBeImplicitlyTaggedPrimitive(sequence.valueBlock.value[0], originalItem1, 0);
        expectItemToBeImplicitlyTaggedPrimitive(sequence.valueBlock.value[1], originalItem2, 1);
    });
    function expectItemToBeImplicitlyTaggedPrimitive(item, itemExplicitlyTagged, expectedTagNumber) {
        if (item instanceof Primitive) {
            expect.fail('Item is not a primitive');
        }
        const itemTyped = item;
        expect(itemTyped.idBlock).toEqual(expect.objectContaining({ tagClass: 3, tagNumber: expectedTagNumber }));
        expect(itemTyped.valueBlock.valueHex).toEqual(itemExplicitlyTagged.valueBlock.valueHex);
    }
});
describe('derSerializeHomogeneousSequence', () => {
    test('An empty input should result in an empty sequence', () => {
        const serialization = derSerializeHomogeneousSequence([]);
        const deserialization = derDeserialize(serialization);
        expect(deserialization.valueBlock.value).toHaveLength(0);
    });
    test('Values should be explicitly tagged', () => {
        const item1 = new VisibleString({ value: 'foo' });
        const item2 = new OctetString({ valueHex: arrayBufferFrom('bar') });
        const serialization = derSerializeHomogeneousSequence([item1, item2]);
        const deserialization = derDeserialize(serialization);
        expect(deserialization.valueBlock.value).toHaveLength(2);
        expectArrayBuffersToEqual(item1.toBER(), deserialization.valueBlock.value[0].toBER());
        expectArrayBuffersToEqual(item2.toBER(), deserialization.valueBlock.value[1].toBER());
    });
});
describe('makeHeterogeneousSequenceSchema', () => {
    const EMPTY_SEQUENCE_SERIALIZED = new Sequence().toBER();
    const PRIMITIVE_ITEM = new Primitive({ valueHex: arrayBufferFrom('primitive') });
    const SINGLE_ITEM_SEQUENCE_SERIALIZED = makeImplicitlyTaggedSequence(PRIMITIVE_ITEM).toBER();
    test('Schema name should be honored', () => {
        const schemaName = 'Foo';
        const schema = makeHeterogeneousSequenceSchema(schemaName, []);
        expect(schema).toHaveProperty('name', schemaName);
    });
    test('Primitive values should remain as such', () => {
        const item = new Primitive({ name: 'item' });
        const schema = makeHeterogeneousSequenceSchema('Foo', [item]);
        expect(schema.valueBlock.value).toHaveLength(1);
        expect(schema.valueBlock.value[0]).toBeInstanceOf(Primitive);
    });
    test('Constructed items should remain as such', () => {
        const item = new Constructed({ name: 'item' });
        const schema = makeHeterogeneousSequenceSchema('Foo', [item]);
        expect(schema.valueBlock.value).toHaveLength(1);
        expect(schema.valueBlock.value[0]).toBeInstanceOf(Constructed);
    });
    test('Items should be implicitly tagged', () => {
        const item1 = new Primitive({ name: 'item1' });
        const item2 = new Constructed({ name: 'item2' });
        const schema = makeHeterogeneousSequenceSchema('Foo', [item1, item2]);
        expect(schema.valueBlock.value).toHaveLength(2);
        expect(schema.valueBlock.value[0]).toHaveProperty('idBlock', expect.objectContaining({ tagClass: 3, tagNumber: 0 }));
        expect(schema.valueBlock.value[1]).toHaveProperty('idBlock', expect.objectContaining({ tagClass: 3, tagNumber: 1 }));
    });
    test('Item names should be honored', () => {
        const item = new Primitive({ name: 'item' });
        const schema = makeHeterogeneousSequenceSchema('Foo', [item]);
        expect(schema.valueBlock.value[0]).toHaveProperty('name', item.name);
    });
    test('Optional items should remain as such', () => {
        const item = new Primitive({ name: 'item', optional: true });
        const schema = makeHeterogeneousSequenceSchema('Foo', [item]);
        expect(verifySchema(EMPTY_SEQUENCE_SERIALIZED, schema)).toHaveProperty('verified', true);
        expect(verifySchema(SINGLE_ITEM_SEQUENCE_SERIALIZED, schema)).toHaveProperty('verified', true);
    });
    test('Required items should remain as such', () => {
        const item = new Primitive({ name: 'item', optional: false });
        const schema = makeHeterogeneousSequenceSchema('Foo', [item]);
        expect(verifySchema(EMPTY_SEQUENCE_SERIALIZED, schema)).toHaveProperty('verified', false);
        expect(verifySchema(SINGLE_ITEM_SEQUENCE_SERIALIZED, schema)).toHaveProperty('verified', true);
    });
    test('Items should be required by default', () => {
        const item = new Primitive({ name: 'item' });
        const schema = makeHeterogeneousSequenceSchema('Foo', [item]);
        expect(verifySchema(EMPTY_SEQUENCE_SERIALIZED, schema)).toHaveProperty('verified', false);
        expect(verifySchema(SINGLE_ITEM_SEQUENCE_SERIALIZED, schema)).toHaveProperty('verified', true);
    });
});
describe('dateToASN1DateTimeInUTC', () => {
    const textDecoder = new TextDecoder();
    test('Date should be serialized with UTC and second-level precision', () => {
        const nonUtcDate = new Date('01 Jan 2019 12:00:00 GMT+11:00');
        const datetimeBlock = dateToASN1DateTimeInUTC(nonUtcDate);
        expect(textDecoder.decode(datetimeBlock.valueBlock.valueHex)).toEqual('20190101010000');
    });
    test('Date should lose millisecond precision', () => {
        const nonUtcDate = new Date('01 Jan 2019 12:00:00.345 GMT+11:00');
        const datetimeBlock = dateToASN1DateTimeInUTC(nonUtcDate);
        expect(textDecoder.decode(datetimeBlock.valueBlock.valueHex)).toEqual('20190101010000');
    });
});
describe('asn1DateTimeToDate', () => {
    const NOW = new Date();
    NOW.setMilliseconds(0);
    test('Date with second-level precision should be accepted', async () => {
        const dateTimeASN1 = dateToASN1DateTimeInUTC(NOW);
        const datePrimitive = new Primitive({
            idBlock: { tagClass: 3, tagNumber: 0 },
            valueHex: dateTimeASN1.valueBlock.toBER(),
        });
        const dateDeserialized = asn1DateTimeToDate(datePrimitive);
        expect(dateDeserialized).toEqual(NOW);
    });
    test('Date with date-level precision should be accepted', async () => {
        const dateString = moment.utc(NOW).format('YYYYMMDD');
        const datePrimitive = new Primitive({
            idBlock: { tagClass: 3, tagNumber: 0 },
            valueHex: arrayBufferFrom(dateString),
        });
        const dateDeserialized = asn1DateTimeToDate(datePrimitive);
        const expectedDate = new Date(moment.utc(NOW).format('YYYY-MM-DD'));
        expect(dateDeserialized).toEqual(expectedDate);
    });
    test('Date not serialized as an ASN.1 DATE-TIME should be refused', async () => {
        const invalidDateTimeASN1 = new Primitive({
            idBlock: { tagClass: 3, tagNumber: 0 },
            valueHex: arrayBufferFrom('invalid date'),
        });
        expect(() => asn1DateTimeToDate(invalidDateTimeASN1)).toThrowWithMessage(InvalidMessageError, /^Date is not serialized as an ASN.1 DATE-TIME/);
    });
});
//# sourceMappingURL=asn1.spec.js.map