import WebCrypto from 'node-webcrypto-ossl';
import * as pkijs from 'pkijs';
import { getPkijsCrypto } from './_utils';

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
