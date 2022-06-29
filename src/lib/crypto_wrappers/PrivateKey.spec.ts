import { PrivateKey } from './PrivateKey';
import { MockAesKwProvider } from './webcrypto/_test_utils';
import { AwalaAesKwProvider } from './webcrypto/AwalaAesKwProvider';

describe('constructor', () => {
  const PROVIDER = new AwalaAesKwProvider(new MockAesKwProvider());

  test('Key type should be private', () => {
    const key = new PrivateKey(PROVIDER);

    expect(key.type).toEqual('private');
  });

  test('Provider should be honoured', () => {
    const key = new PrivateKey(PROVIDER);

    expect(key.provider).toEqual(PROVIDER);
  });
});
