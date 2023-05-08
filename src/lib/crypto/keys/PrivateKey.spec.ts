import { HashingAlgorithm } from '../algorithms';
import { PrivateKey, RsaPssPrivateKey } from './PrivateKey';
import { MockAesKwProvider } from '../webcrypto/_test_utils';
import { AwalaAesKwProvider } from '../webcrypto/AwalaAesKwProvider';

const PROVIDER = new AwalaAesKwProvider(new MockAesKwProvider());

describe('PrivateKey', () => {
  const ALGORITHM: KeyAlgorithm = { name: 'RSA-PSS' };

  test('Key type should be private', () => {
    const key = new PrivateKey(ALGORITHM, PROVIDER);

    expect(key.type).toEqual('private');
  });

  test('Key should be extractable', () => {
    const key = new PrivateKey(ALGORITHM, PROVIDER);

    expect(key.extractable).toBeTrue();
  });

  test('Algorithm should be honoured', () => {
    const key = new PrivateKey(ALGORITHM, PROVIDER);

    expect(key.algorithm).toEqual(ALGORITHM);
  });

  test('Provider should be honoured', () => {
    const key = new PrivateKey(ALGORITHM, PROVIDER);

    expect(key.provider).toEqual(PROVIDER);
  });
});

describe('RsaPssPrivateKey', () => {
  const HASHING_ALGORITHM: HashingAlgorithm = 'SHA-384';

  test('Key usages should only allow signing', () => {
    const key = new RsaPssPrivateKey(HASHING_ALGORITHM, PROVIDER);

    expect(key.usages).toEqual(['sign']);
  });

  test('Hashing algorithm should be added to key algorithm', () => {
    const key = new RsaPssPrivateKey(HASHING_ALGORITHM, PROVIDER);

    expect(key.algorithm).toEqual({
      hash: { name: HASHING_ALGORITHM },
      name: 'RSA-PSS',
    });
  });

  test('Provider should be honoured', () => {
    const key = new RsaPssPrivateKey(HASHING_ALGORITHM, PROVIDER);

    expect(key.provider).toEqual(PROVIDER);
  });
});
