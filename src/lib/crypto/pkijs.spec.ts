import { SubtleCrypto } from 'webcrypto-core';

import { RsaPssPrivateKey } from './keys/PrivateKey';
import { MockRsaPssProvider } from './webcrypto/_test_utils';
import { getEngineForKey, NODE_ENGINE } from './pkijs';
import { CryptoKeyWithProvider } from './keys/CryptoKeyWithProvider';

describe('getEngineForKey', () => {
  const PROVIDER = new MockRsaPssProvider();

  test('Default engine should be returned if CryptoKey is used', () => {
    const engine = getEngineForKey({} as unknown as CryptoKeyWithProvider);

    expect(engine).toBe(NODE_ENGINE);
  });

  test('Nameless engine should be returned if PrivateKey is used', () => {
    const key = new RsaPssPrivateKey('SHA-256', PROVIDER);

    const engine = getEngineForKey(key);

    expect(engine?.name).toBeEmpty();
  });

  test('Engine crypto should use provider from private key', () => {
    const key = new RsaPssPrivateKey('SHA-256', PROVIDER);

    const engine = getEngineForKey(key);

    expect((engine?.crypto.subtle as SubtleCrypto).providers.get(PROVIDER.name)).toBe(PROVIDER);
  });

  test('Same engine should be returned if multiple keys share provider', () => {
    // This is to check engines are being cached
    const key1 = new RsaPssPrivateKey('SHA-256', PROVIDER);
    const key2 = new RsaPssPrivateKey('SHA-256', PROVIDER);

    const engine1 = getEngineForKey(key1);
    const engine2 = getEngineForKey(key2);

    expect(engine1).toBe(engine2);
  });

  test('Different engines should be returned if keys use different providers', () => {
    const key1 = new RsaPssPrivateKey('SHA-256', PROVIDER);
    const key2 = new RsaPssPrivateKey('SHA-256', new MockRsaPssProvider());

    const engine1 = getEngineForKey(key1);
    const engine2 = getEngineForKey(key2);

    expect(engine1).not.toBe(engine2);
  });
});
