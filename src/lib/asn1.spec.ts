import { OctetString, Primitive, Sequence, verifySchema, VisibleString } from 'asn1js';
import { arrayBufferFrom } from './_test_utils';
import { serializeSequence } from './asn1';

describe('serializeSequence', () => {
  test('An empty input should result in an empty sequence', () => {
    const serialization = serializeSequence();

    const schema = new Sequence();
    const schemaVerification = verifySchema(serialization, schema);

    expect(schemaVerification.verified).toBeTrue();
    expect(schemaVerification.result.valueBlock.value).toHaveLength(0);
  });

  test('Values should be implicitly tagged', () => {
    const item1 = new VisibleString({ value: 'foo' });
    const item2 = new OctetString({ valueHex: arrayBufferFrom('bar') } as any);
    const serialization = serializeSequence(item1, item2);

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
