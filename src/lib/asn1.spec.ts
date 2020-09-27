import { Constructed, OctetString, Primitive, Sequence, verifySchema, VisibleString } from 'asn1js';
import moment from 'moment';
import { TextDecoder } from 'util';

import { arrayBufferFrom, expectBuffersToEqual } from './_test_utils';
import {
  asn1DateTimeToDate,
  dateToASN1DateTimeInUTC,
  derSerializeHeterogeneousSequence,
  derSerializeHomogeneousSequence,
} from './asn1';
import { derDeserialize } from './crypto_wrappers/_utils';
import InvalidMessageError from './messages/InvalidMessageError';

describe('derSerializeHeterogeneousSequence', () => {
  test('An empty input should result in an empty sequence', () => {
    const serialization = derSerializeHeterogeneousSequence();

    const schema = new Sequence();
    const schemaVerification = verifySchema(serialization, schema);

    expect(schemaVerification.verified).toBeTrue();
    expect(schemaVerification.result.valueBlock.value).toHaveLength(0);
  });

  test('Primitive values should be implicitly tagged', () => {
    const item = new OctetString({ valueHex: arrayBufferFrom('foo') } as any);

    const serialization = derSerializeHeterogeneousSequence(item);

    const schema = new Sequence({
      name: 'Dummy',
      value: [
        new Primitive({
          idBlock: { tagClass: 3, tagNumber: 0 },
          name: 'item',
          optional: false,
        } as any),
      ],
    } as any);

    const schemaVerification = verifySchema(serialization, schema);
    expect(schemaVerification.verified).toBeTrue();
    expect(schemaVerification.result.Dummy.item).toHaveProperty(
      'valueBlock.valueHex',
      item.valueBlock.valueHex,
    );
    expect(schemaVerification.result.Dummy.item).toHaveProperty(
      'valueBlock.valueHex',
      item.valueBlock.valueHex,
    );
  });

  test('Constructed items should be implicitly tagged', () => {
    const subitem1 = new VisibleString({ value: 'foo' });
    const subitem2 = new VisibleString({ value: 'bar' });
    const item = new Sequence({ value: [subitem1, subitem2] } as any);

    const serialization = derSerializeHeterogeneousSequence(item);

    const schema = new Sequence({
      name: 'Dummy',
      value: [
        new Constructed({
          idBlock: { tagClass: 3, tagNumber: 0 },
          name: 'item',
          optional: false,
          value: [subitem1, subitem2],
        } as any),
      ],
    } as any);

    const schemaVerification = verifySchema(serialization, schema);
    expect(schemaVerification.verified).toBeTrue();
    expect(schemaVerification.result.Dummy.item.valueBlock.value[0]).toHaveProperty(
      'valueBlock.valueHex',
      subitem1.valueBlock.valueHex,
    );
    expect(schemaVerification.result.Dummy.item.valueBlock.value[0]).toHaveProperty(
      'valueBlock.valueHex',
      subitem2.valueBlock.valueHex,
    );
  });

  test('Multiple values should be implicitly tagged', () => {
    const item1 = new VisibleString({ value: 'foo' });
    const item2 = new OctetString({ valueHex: arrayBufferFrom('bar') } as any);
    const serialization = derSerializeHeterogeneousSequence(item1, item2);

    const schema = new Sequence({
      name: 'Dummy',
      value: [
        new Primitive({
          idBlock: { tagClass: 3, tagNumber: 0 },
          name: 'item1',
          optional: false,
        } as any),
        new Primitive({
          idBlock: { tagClass: 3, tagNumber: 1 },
          name: 'item2',
          optional: false,
        } as any),
      ],
    } as any);

    const schemaVerification = verifySchema(serialization, schema);
    expect(schemaVerification.verified).toBeTrue();
    expect(schemaVerification.result.Dummy.item1).toHaveProperty(
      'valueBlock.valueHex',
      item1.valueBlock.valueHex,
    );
    expect(schemaVerification.result.Dummy.item2).toHaveProperty(
      'valueBlock.valueHex',
      item2.valueBlock.valueHex,
    );
  });
});

describe('derSerializeHomogeneousSequence', () => {
  test('An empty input should result in an empty sequence', () => {
    const serialization = derSerializeHomogeneousSequence([]);

    const deserialization = derDeserialize(serialization) as Sequence;
    expect(deserialization.valueBlock.value).toHaveLength(0);
  });

  test('Values should be explicitly tagged', () => {
    const item1 = new VisibleString({ value: 'foo' });
    const item2 = new OctetString({ valueHex: arrayBufferFrom('bar') } as any);

    const serialization = derSerializeHomogeneousSequence([item1, item2]);

    const deserialization = derDeserialize(serialization) as Sequence;
    expect(deserialization.valueBlock.value).toHaveLength(2);
    expectBuffersToEqual(item1.toBER(), deserialization.valueBlock.value[0].toBER());
    expectBuffersToEqual(item2.toBER(), deserialization.valueBlock.value[1].toBER());
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
    } as any);

    const dateDeserialized = asn1DateTimeToDate(datePrimitive);

    expect(dateDeserialized).toEqual(NOW);
  });

  test('Date with date-level precision should be accepted', async () => {
    const dateString = moment.utc(NOW).format('YYYYMMDD');
    const datePrimitive = new Primitive({
      idBlock: { tagClass: 3, tagNumber: 0 },
      valueHex: arrayBufferFrom(dateString),
    } as any);

    const dateDeserialized = asn1DateTimeToDate(datePrimitive);

    const expectedDate = new Date(moment.utc(NOW).format('YYYY-MM-DD'));
    expect(dateDeserialized).toEqual(expectedDate);
  });

  test('Date not serialized as an ASN.1 DATE-TIME should be refused', async () => {
    const invalidDateTimeASN1 = new Primitive({
      idBlock: { tagClass: 3, tagNumber: 0 },
      valueHex: arrayBufferFrom('invalid date'),
    } as any);

    expect(() => asn1DateTimeToDate(invalidDateTimeASN1)).toThrowWithMessage(
      InvalidMessageError,
      /^Date is not serialized as an ASN.1 DATE-TIME/,
    );
  });
});
