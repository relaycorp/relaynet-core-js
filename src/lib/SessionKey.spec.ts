import { derSerializePublicKey } from './crypto_wrappers/keys';
import { SessionKey } from './SessionKey';

describe('generate', () => {
  test('keyId should be randomly generated, 64-bit value', async () => {
    const { sessionKey } = await SessionKey.generate();

    expect(sessionKey.keyId).toBeInstanceOf(Buffer);
    expect(sessionKey.keyId.byteLength).toEqual(8);
  });

  test('publicKey should be output', async () => {
    const { sessionKey } = await SessionKey.generate();

    expect(sessionKey.publicKey.type).toEqual('public');
    expect(sessionKey.publicKey.algorithm.name).toEqual('ECDH');
  });

  test('privateKey should correspond to public key', async () => {
    const { sessionKey, privateKey } = await SessionKey.generate();

    expect(privateKey.type).toEqual('private');
    await expect(derSerializePublicKey(privateKey)).resolves.toEqual(
      await derSerializePublicKey(sessionKey.publicKey),
    );
  });
});
