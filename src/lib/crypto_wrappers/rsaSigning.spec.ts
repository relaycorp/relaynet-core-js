import { ProviderCrypto } from 'webcrypto-core';

import { arrayBufferFrom } from '../_test_utils';
import * as utils from './_utils';
import { generateRSAKeyPair } from './keys';
import { PrivateKey } from './PrivateKey';
import { sign, verify } from './rsaSigning';

const plaintext = arrayBufferFrom('the plaintext');

const pkijsCrypto = utils.getPkijsCrypto();

// tslint:disable-next-line:no-let
let keyPair: CryptoKeyPair;
beforeAll(async () => {
  keyPair = await generateRSAKeyPair();
});

describe('sign', () => {
  const RSA_PSS_PARAMS = {
    hash: { name: 'SHA-256' },
    name: 'RSA-PSS',
    saltLength: 32,
  };

  test('The plaintext should be signed with RSA-PSS, SHA-256 and a salt of 32', async () => {
    const signature = await sign(plaintext, keyPair.privateKey);

    await pkijsCrypto.verify(RSA_PSS_PARAMS, keyPair.publicKey, signature, plaintext);
  });

  test('The plaintext should be signed with PrivateKey if requested', async () => {
    const mockSignature = arrayBufferFrom('signature');
    const mockProvider: Partial<ProviderCrypto> = {
      sign: jest.fn().mockReturnValue(mockSignature),
    };
    const privateKey = new PrivateKey(mockProvider as any);

    const signature = await sign(plaintext, privateKey);

    expect(signature).toBe(mockSignature);
    expect(mockProvider.sign).toBeCalledWith(RSA_PSS_PARAMS, privateKey, plaintext);
  });
});

describe('verify', () => {
  test('Invalid plaintexts should be refused', async () => {
    const anotherKeyPair = await generateRSAKeyPair();
    const signature = await sign(plaintext, anotherKeyPair.privateKey);

    await expect(verify(signature, keyPair.publicKey, plaintext)).resolves.toBeFalse();
  });

  test('Algorithms other than RSA-PSS with SHA-256 and MGF1 should be refused', async () => {
    const algorithmParams = {
      hash: { name: 'SHA-1' },
      name: 'RSA-PSS',
      saltLength: 20,
    };
    const invalidSignature = await pkijsCrypto.sign(algorithmParams, keyPair.privateKey, plaintext);

    await expect(verify(invalidSignature, keyPair.publicKey, plaintext)).resolves.toBeFalse();
  });

  test('Valid signatures should be accepted', async () => {
    const signature = await sign(plaintext, keyPair.privateKey);

    await expect(verify(signature, keyPair.publicKey, plaintext)).resolves.toBeTrue();
  });
});
