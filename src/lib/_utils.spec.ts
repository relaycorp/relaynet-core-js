import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import WebCrypto from 'node-webcrypto-ossl';
import * as pkijs from 'pkijs';

import { deserializeDer, getPkijsCrypto } from './_utils';

jest.mock('pkijs');

describe('getPkijsCrypto', () => {
  test('It should pass on the crypto object it got', () => {
    const webcrypto = new WebCrypto();
    // @ts-ignore
    pkijs.getCrypto.mockReturnValue(webcrypto.subtle);

    const crypto = getPkijsCrypto();
    expect(crypto).toBe(webcrypto.subtle);
  });

  test('It should error out if there is no crypto object', () => {
    // @ts-ignore
    pkijs.getCrypto.mockReturnValue(undefined);

    expect(getPkijsCrypto).toThrow('PKI.js crypto engine is undefined');
  });
});

describe('deserializeDer', () => {
  test('should return ASN.1 object given a valid DER-encoded buffer', () => {
    const asn1Value = new asn1js.Integer({ value: 3 });
    const derValue = asn1Value.toBER(false);

    const deserializedValue = deserializeDer(derValue);
    expect(deserializedValue).toHaveProperty('idBlock.tagClass', asn1Value.idBlock.tagClass);
    expect(deserializedValue).toHaveProperty('idBlock.tagNumber', asn1Value.idBlock.tagNumber);
    expect(deserializedValue).toHaveProperty('valueBlock.valueDec', asn1Value.valueBlock.valueDec);
  });

  test('should fail when passed a non-DER encoded value', () => {
    const invalidDerValue = bufferToArray(Buffer.from('hi'));
    expect(() => deserializeDer(invalidDerValue)).toThrowError(
      new Error('Value is not DER-encoded'),
    );
  });
});
