import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import * as pkijs from 'pkijs';

import { mockSpy } from '../_test_utils';
import { derDeserialize, generateRandom64BitValue } from './_utils';

const mockGetCrypto = mockSpy(jest.spyOn(pkijs, 'getCrypto'));

describe('deserializeDer', () => {
  test('should return ASN.1 object given a valid DER-encoded buffer', () => {
    const asn1Value = new asn1js.Integer({ value: 3 });
    const derValue = asn1Value.toBER(false);

    const deserializedValue = derDeserialize(derValue);
    expect(deserializedValue).toHaveProperty('idBlock.tagClass', asn1Value.idBlock.tagClass);
    expect(deserializedValue).toHaveProperty('idBlock.tagNumber', asn1Value.idBlock.tagNumber);
    expect(deserializedValue).toHaveProperty('valueBlock.valueDec', asn1Value.valueBlock.valueDec);
  });

  test('should fail when passed a non-DER encoded value', () => {
    const invalidDerValue = bufferToArray(Buffer.from('hi'));
    expect(() => derDeserialize(invalidDerValue)).toThrowError(
      new Error('Value is not DER-encoded'),
    );
  });
});

test('generateRandom64BitValue() should generate a cryptographically secure value', () => {
  const expectedBytes: readonly number[] = [1, 2, 3, 4, 5, 6, 7, 8];
  const mockWebcrypto = {
    getRandomValues: jest.fn().mockImplementation((array: Uint8Array) => array.set(expectedBytes)),
  };
  mockGetCrypto.mockReturnValue(mockWebcrypto as any);

  const randomValue = generateRandom64BitValue();

  expect(randomValue).toBeInstanceOf(ArrayBuffer);
  expect(randomValue).toHaveProperty('byteLength', 8);

  const expectedGeneratedValue = new ArrayBuffer(8);
  const expectedGeneratedValueView = new Uint8Array(expectedGeneratedValue);
  expectedGeneratedValueView.set(expectedBytes);
  expect(randomValue).toEqual(expectedGeneratedValue);
});
