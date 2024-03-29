import { HashingAlgorithm, RSAModulus } from '../crypto/algorithms';
import { SessionKeyPair } from '../SessionKeyPair';
import { KeyStoreError } from './KeyStoreError';
import { SessionPrivateKeyData } from './PrivateKeyStore';
import { MockPrivateKeyStore } from './testMocks';
import { UnknownKeyError } from './UnknownKeyError';
import { derSerializePrivateKey, derSerializePublicKey } from '../crypto/keys/serialisation';
import { getIdFromIdentityKey } from '../crypto/keys/digest';

const MOCK_STORE = new MockPrivateKeyStore();
beforeEach(() => {
  MOCK_STORE.clear();
});

describe('Identity keys', () => {
  describe('generateIdentityKeyPair', () => {
    test('RSA modulus 2048 should be generated by default', async () => {
      const keyPair = await MOCK_STORE.generateIdentityKeyPair();

      expect(keyPair.privateKey.algorithm).toHaveProperty('modulusLength', 2048);
    });

    test.each([2048, 3072, 4096] as readonly RSAModulus[])(
      'RSA modulus %s should be used if requested',
      async (modulus) => {
        const keyPair = await MOCK_STORE.generateIdentityKeyPair({ modulus });

        expect(keyPair.privateKey.algorithm).toHaveProperty('modulusLength', modulus);
      },
    );

    test('SHA-256 should be used by default', async () => {
      const keyPair = await MOCK_STORE.generateIdentityKeyPair();

      expect(keyPair.privateKey.algorithm).toHaveProperty('hash.name', 'SHA-256');
    });

    test.each(['SHA-256', 'SHA-384', 'SHA-512'] as readonly HashingAlgorithm[])(
      'Hashing algorithm %s should be used if requested',
      async (hashingAlgorithm) => {
        const keyPair = await MOCK_STORE.generateIdentityKeyPair({ hashingAlgorithm });

        expect(keyPair.privateKey.algorithm).toHaveProperty('hash.name', hashingAlgorithm);
      },
    );

    test('Id should be returned', async () => {
      const keyPair = await MOCK_STORE.generateIdentityKeyPair();

      expect(keyPair.id).toEqual(await getIdFromIdentityKey(keyPair.publicKey));
    });

    test('Public key should correspond to private key', async () => {
      const keyPair = await MOCK_STORE.generateIdentityKeyPair();

      const expectedPublicKeySerialized = await derSerializePublicKey(keyPair.privateKey);
      await expect(derSerializePublicKey(keyPair.publicKey)).resolves.toEqual(
        expectedPublicKeySerialized,
      );
    });

    test('Key should be stored', async () => {
      const { id, privateKey } = await MOCK_STORE.generateIdentityKeyPair();

      expect(MOCK_STORE.identityKeys).toHaveProperty(id, privateKey);
    });

    test('Errors should be wrapped', async () => {
      const store = new MockPrivateKeyStore(true);

      await expect(store.generateIdentityKeyPair()).rejects.toThrowWithMessage(
        KeyStoreError,
        /^Failed to save key for \w+: Denied/,
      );
    });
  });
});

describe('Session keys', () => {
  let sessionKeyPair: SessionKeyPair;
  let sessionKeyIdHex: string;
  beforeAll(async () => {
    sessionKeyPair = await SessionKeyPair.generate();
    sessionKeyIdHex = sessionKeyPair.sessionKey.keyId.toString('hex');
  });

  const NODE_ID = '0deadc0de';
  const PEER_ID = '0deadbeef';

  describe('saveSessionKey', () => {
    test('Unbound key should be stored', async () => {
      await MOCK_STORE.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        NODE_ID,
      );

      expect(MOCK_STORE.sessionKeys).toHaveProperty<SessionPrivateKeyData>(sessionKeyIdHex, {
        keySerialized: await derSerializePrivateKey(sessionKeyPair.privateKey),
        nodeId: NODE_ID,
      });
    });

    test('Bound key should be stored', async () => {
      await MOCK_STORE.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        NODE_ID,
        PEER_ID,
      );

      expect(MOCK_STORE.sessionKeys).toHaveProperty<SessionPrivateKeyData>(sessionKeyIdHex, {
        keySerialized: await derSerializePrivateKey(sessionKeyPair.privateKey),
        peerId: PEER_ID,
        nodeId: NODE_ID,
      });
    });

    test('Errors should be wrapped', async () => {
      const store = new MockPrivateKeyStore(true);

      await expect(
        store.saveSessionKey(sessionKeyPair.privateKey, sessionKeyPair.sessionKey.keyId, NODE_ID),
      ).rejects.toThrowWithMessage(KeyStoreError, `Failed to save key ${sessionKeyIdHex}: Denied`);
    });
  });

  describe('retrieveUnboundSessionPublicKey', () => {
    test('Existing key should be returned', async () => {
      await MOCK_STORE.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        NODE_ID,
      );

      const data = await MOCK_STORE.retrieveUnboundSessionPublicKey(NODE_ID);

      expect(data?.keyId).toMatchObject(sessionKeyPair.sessionKey.keyId);
      expect(data!.publicKey.type).toBe('public');
      expect(await derSerializePublicKey(data!.publicKey)).toEqual(
        await derSerializePublicKey(sessionKeyPair.sessionKey.publicKey),
      );
    });

    test('Null should be returned if node has no unbound keys', async () => {
      await expect(MOCK_STORE.retrieveUnboundSessionPublicKey(NODE_ID)).resolves.toBeNull();
    });
  });

  describe('retrieveSessionKey', () => {
    test('Initial session keys should be returned', async () => {
      await MOCK_STORE.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        NODE_ID,
      );

      const privateKey = await MOCK_STORE.retrieveSessionKey(
        sessionKeyPair.sessionKey.keyId,
        NODE_ID,
        PEER_ID,
      );

      expect(await derSerializePrivateKey(privateKey)).toEqual(
        await derSerializePrivateKey(privateKey),
      );
    });

    test('Bound session keys should be returned', async () => {
      await MOCK_STORE.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        NODE_ID,
        PEER_ID,
      );

      const privateKey = await MOCK_STORE.retrieveSessionKey(
        sessionKeyPair.sessionKey.keyId,
        NODE_ID,
        PEER_ID,
      );

      expect(await derSerializePrivateKey(privateKey)).toEqual(
        await derSerializePrivateKey(privateKey),
      );
    });

    test('UnknownKeyError should be thrown if key pair does not exist', async () => {
      await expect(
        MOCK_STORE.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, NODE_ID, PEER_ID),
      ).rejects.toThrowWithMessage(UnknownKeyError, `Key ${sessionKeyIdHex} does not exist`);
    });

    test('Key should not be returned if owned by different node', async () => {
      await MOCK_STORE.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        NODE_ID,
        PEER_ID,
      );

      await expect(
        MOCK_STORE.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, `not-${NODE_ID}`, PEER_ID),
      ).rejects.toThrowWithMessage(UnknownKeyError, 'Key is owned by a different node');
    });

    test('Keys bound to another recipient should not be returned', async () => {
      await MOCK_STORE.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPair.sessionKey.keyId,
        NODE_ID,
        PEER_ID,
      );

      const invalidPeerId = `not ${PEER_ID}`;
      await expect(
        MOCK_STORE.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, NODE_ID, invalidPeerId),
      ).rejects.toThrowWithMessage(
        UnknownKeyError,
        `Session key ${sessionKeyIdHex} is bound to another recipient ` +
          `(${PEER_ID}, not ${invalidPeerId})`,
      );
    });

    test('Errors should be wrapped', async () => {
      const store = new MockPrivateKeyStore(false, true);

      await expect(
        store.retrieveSessionKey(sessionKeyPair.sessionKey.keyId, NODE_ID, PEER_ID),
      ).rejects.toEqual(new KeyStoreError('Failed to retrieve key: Denied'));
    });
  });
});
