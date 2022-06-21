import { Crypto } from '@peculiar/webcrypto';
import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import * as pkijs from 'pkijs';
import { derDeserialize, generateRandom64BitValue, getPkijsCrypto } from './_utils';
const stubCrypto = new Crypto();
jest.mock('pkijs');
describe('getPkijsCrypto', () => {
    test('It should pass on the crypto object it got', () => {
        // @ts-ignore
        pkijs.getCrypto.mockReturnValue(stubCrypto.subtle);
        const crypto = getPkijsCrypto();
        expect(crypto).toBe(stubCrypto.subtle);
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
        const deserializedValue = derDeserialize(derValue);
        expect(deserializedValue).toHaveProperty('idBlock.tagClass', asn1Value.idBlock.tagClass);
        expect(deserializedValue).toHaveProperty('idBlock.tagNumber', asn1Value.idBlock.tagNumber);
        expect(deserializedValue).toHaveProperty('valueBlock.valueDec', asn1Value.valueBlock.valueDec);
    });
    test('should fail when passed a non-DER encoded value', () => {
        const invalidDerValue = bufferToArray(Buffer.from('hi'));
        expect(() => derDeserialize(invalidDerValue)).toThrowError(new Error('Value is not DER-encoded'));
    });
});
test('generateRandom64BitValue() should generate a cryptographically secure value', () => {
    const expectedBytes = [1, 2, 3, 4, 5, 6, 7, 8];
    const mockWebcrypto = {
        getRandomValues: jest.fn().mockImplementation((array) => array.set(expectedBytes)),
    };
    // @ts-ignore
    pkijs.getCrypto.mockReset();
    // @ts-ignore
    pkijs.getCrypto.mockReturnValue(mockWebcrypto);
    const randomValue = generateRandom64BitValue();
    expect(randomValue).toBeInstanceOf(ArrayBuffer);
    expect(randomValue).toHaveProperty('byteLength', 8);
    const expectedGeneratedValue = new ArrayBuffer(8);
    const expectedGeneratedValueView = new Uint8Array(expectedGeneratedValue);
    expectedGeneratedValueView.set(expectedBytes);
    expect(randomValue).toEqual(expectedGeneratedValue);
});
//# sourceMappingURL=_utils.spec.js.map