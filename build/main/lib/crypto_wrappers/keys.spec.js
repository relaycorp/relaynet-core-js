"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const crypto_1 = require("crypto");
const pkijs_1 = require("pkijs");
const _test_utils_1 = require("../_test_utils");
const keys_1 = require("./keys");
describe('generateRsaKeyPair', () => {
    test('Keys should be RSA-PSS', async () => {
        const keyPair = await (0, keys_1.generateRSAKeyPair)();
        expect(keyPair.publicKey.algorithm.name).toEqual('RSA-PSS');
        expect(keyPair.privateKey.algorithm.name).toEqual('RSA-PSS');
    });
    test('Keys should be extractable', async () => {
        const keyPair = await (0, keys_1.generateRSAKeyPair)();
        expect(keyPair.publicKey.extractable).toEqual(true);
        expect(keyPair.privateKey.extractable).toEqual(true);
    });
    test('Key usages should be used for signatures only', async () => {
        const keyPair = await (0, keys_1.generateRSAKeyPair)();
        expect(keyPair).toHaveProperty('publicKey.usages', ['verify']);
        expect(keyPair).toHaveProperty('privateKey.usages', ['sign']);
    });
    describe('Modulus', () => {
        test('Default modulus should be 2048', async () => {
            const keyPair = await (0, keys_1.generateRSAKeyPair)();
            expect(keyPair.publicKey.algorithm).toHaveProperty('modulusLength', 2048);
            expect(keyPair.privateKey.algorithm).toHaveProperty('modulusLength', 2048);
        });
        test.each([2048, 3072, 4096])('Modulus %s should be used if explicitly requested', async () => {
            const modulus = 4096;
            const keyPair = await (0, keys_1.generateRSAKeyPair)({ modulus });
            expect(keyPair.publicKey.algorithm).toHaveProperty('modulusLength', modulus);
            expect(keyPair.privateKey.algorithm).toHaveProperty('modulusLength', modulus);
        });
        test('Modulus < 2048 should not supported', async () => {
            await expect((0, keys_1.generateRSAKeyPair)({ modulus: 1024 })).rejects.toThrow('RSA modulus must be => 2048 per RS-018 (got 1024)');
        });
    });
    describe('Hashing algorithm', () => {
        test('SHA-256 should be used by default', async () => {
            const keyPair = await (0, keys_1.generateRSAKeyPair)();
            expect(keyPair.publicKey.algorithm).toHaveProperty('hash.name', 'SHA-256');
            expect(keyPair.privateKey.algorithm).toHaveProperty('hash.name', 'SHA-256');
        });
        test.each(['SHA-384', 'SHA-512'])('%s hashing should be supported', async (hashingAlgorithm) => {
            const keyPair = await (0, keys_1.generateRSAKeyPair)({ hashingAlgorithm });
            expect(keyPair.publicKey.algorithm).toHaveProperty('hash.name', hashingAlgorithm);
            expect(keyPair.privateKey.algorithm).toHaveProperty('hash.name', hashingAlgorithm);
        });
        test('SHA-1 should not be supported', async () => {
            await expect((0, keys_1.generateRSAKeyPair)({ hashingAlgorithm: 'SHA-1' })).rejects.toThrow('SHA-1 is disallowed by RS-018');
        });
    });
});
describe('generateDHKeyPair', () => {
    test('The result should be a DH key pair', async () => {
        const keyPair = await (0, keys_1.generateECDHKeyPair)();
        expect(keyPair).toHaveProperty('privateKey.algorithm.name', 'ECDH');
        expect(keyPair).toHaveProperty('publicKey.algorithm.name', 'ECDH');
    });
    test('NIST P-256 curve should be used by default', async () => {
        const keyPair = await (0, keys_1.generateECDHKeyPair)();
        expect(keyPair).toHaveProperty('privateKey.algorithm.namedCurve', 'P-256');
        expect(keyPair).toHaveProperty('publicKey.algorithm.namedCurve', 'P-256');
    });
    test.each([['P-384', 'P-521']])('%s should also be supported', async (curveName) => {
        const keyPair = await (0, keys_1.generateECDHKeyPair)(curveName);
        expect(keyPair).toHaveProperty('privateKey.algorithm.namedCurve', curveName);
        expect(keyPair).toHaveProperty('publicKey.algorithm.namedCurve', curveName);
    });
    test('The key pair should be extractable', async () => {
        const keyPair = await (0, keys_1.generateECDHKeyPair)();
        expect(keyPair).toHaveProperty('privateKey.extractable', true);
        expect(keyPair).toHaveProperty('publicKey.extractable', true);
    });
    test('deriveKey and deriveBits should be the only uses of the private keys', async () => {
        const keyPair = await (0, keys_1.generateECDHKeyPair)();
        expect(keyPair.privateKey.usages).toContainValues(['deriveBits', 'deriveKey']);
        expect(keyPair.publicKey.usages).toBeEmpty();
    });
});
describe('getRSAPublicKeyFromPrivate', () => {
    test('Public key should be returned', async () => {
        const keyPair = await (0, keys_1.generateRSAKeyPair)();
        const publicKey = await (0, keys_1.getRSAPublicKeyFromPrivate)(keyPair.privateKey);
        // It's important to check we got a public key before checking its serialisation. If we try to
        // serialise a private key with SPKI, it'd internally use the public key first.
        expect(publicKey.type).toEqual(keyPair.publicKey.type);
        await expect((0, keys_1.derSerializePublicKey)(publicKey)).resolves.toEqual(await (0, keys_1.derSerializePublicKey)(keyPair.publicKey));
    });
    test('Public key should honour algorithm parameters', async () => {
        const keyPair = await (0, keys_1.generateRSAKeyPair)();
        const publicKey = await (0, keys_1.getRSAPublicKeyFromPrivate)(keyPair.privateKey);
        expect(publicKey.algorithm).toEqual(keyPair.publicKey.algorithm);
    });
    test('Public key should only be used to verify signatures', async () => {
        const keyPair = await (0, keys_1.generateRSAKeyPair)();
        const publicKey = await (0, keys_1.getRSAPublicKeyFromPrivate)(keyPair.privateKey);
        expect(publicKey.usages).toEqual(['verify']);
    });
});
describe('Key serializers', () => {
    let stubKeyPair;
    beforeAll(async () => {
        stubKeyPair = await (0, keys_1.generateRSAKeyPair)();
    });
    const stubExportedKeyDer = (0, _test_utils_1.arrayBufferFrom)('Hey');
    const mockExportKey = jest.spyOn(pkijs_1.CryptoEngine.prototype, 'exportKey');
    beforeEach(async () => {
        mockExportKey.mockReset();
        mockExportKey.mockResolvedValue(stubExportedKeyDer);
    });
    afterAll(() => {
        mockExportKey.mockRestore();
    });
    test('derSerializePublicKey should convert public key to buffer', async () => {
        const publicKeyDer = await (0, keys_1.derSerializePublicKey)(stubKeyPair.publicKey);
        expect(publicKeyDer).toEqual(Buffer.from(stubExportedKeyDer));
        expect(mockExportKey).toBeCalledTimes(1);
        expect(mockExportKey).toBeCalledWith('spki', stubKeyPair.publicKey);
    });
    test('derSerializePrivateKey should convert private key to buffer', async () => {
        const privateKeyDer = await (0, keys_1.derSerializePrivateKey)(stubKeyPair.privateKey);
        expect(privateKeyDer).toEqual(Buffer.from(stubExportedKeyDer));
        expect(mockExportKey).toBeCalledTimes(1);
        expect(mockExportKey).toBeCalledWith('pkcs8', stubKeyPair.privateKey);
    });
});
describe('Key deserializers', () => {
    const stubKeyDer = Buffer.from('Hey');
    const rsaAlgorithmOptions = { name: 'RSA-PSS', hash: { name: 'SHA-256' } };
    const ecdhCurveName = 'P-384';
    let stubKeyPair;
    beforeAll(async () => {
        stubKeyPair = await (0, keys_1.generateRSAKeyPair)();
    });
    const mockImportKey = jest.spyOn(pkijs_1.CryptoEngine.prototype, 'importKey');
    beforeEach(async () => {
        mockImportKey.mockClear();
    });
    afterAll(() => {
        mockImportKey.mockRestore();
    });
    test('derDeserializeRSAPublicKey should convert DER public key to RSA key', async () => {
        mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);
        const publicKey = await (0, keys_1.derDeserializeRSAPublicKey)(stubKeyDer, rsaAlgorithmOptions);
        expect(publicKey).toBe(stubKeyPair.publicKey);
        expect(mockImportKey).toBeCalledTimes(1);
        expect(mockImportKey).toBeCalledWith('spki', (0, buffer_to_arraybuffer_1.default)(stubKeyDer), rsaAlgorithmOptions, true, ['verify']);
    });
    test('derDeserializeRSAPublicKey should default to RSA-PSS with SHA-256', async () => {
        mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);
        const publicKey = await (0, keys_1.derDeserializeRSAPublicKey)(stubKeyDer);
        expect(publicKey).toBe(stubKeyPair.publicKey);
        expect(mockImportKey).toBeCalledTimes(1);
        expect(mockImportKey).toBeCalledWith('spki', (0, buffer_to_arraybuffer_1.default)(stubKeyDer), rsaAlgorithmOptions, true, ['verify']);
    });
    test('derDeserializeRSAPublicKey should accept an ArrayBuffer serialization', async () => {
        mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);
        const keyDerArrayBuffer = (0, _test_utils_1.arrayBufferFrom)(stubKeyDer);
        const publicKey = await (0, keys_1.derDeserializeRSAPublicKey)(keyDerArrayBuffer, rsaAlgorithmOptions);
        expect(publicKey).toBe(stubKeyPair.publicKey);
        expect(mockImportKey).toBeCalledTimes(1);
        expect(mockImportKey).toBeCalledWith('spki', keyDerArrayBuffer, rsaAlgorithmOptions, true, [
            'verify',
        ]);
    });
    test('derDeserializeRSAPrivateKey should convert DER private key to RSA key', async () => {
        mockImportKey.mockResolvedValueOnce(stubKeyPair.privateKey);
        const privateKey = await (0, keys_1.derDeserializeRSAPrivateKey)(stubKeyDer, rsaAlgorithmOptions);
        expect(privateKey).toBe(stubKeyPair.privateKey);
        expect(mockImportKey).toBeCalledTimes(1);
        expect(mockImportKey).toBeCalledWith('pkcs8', (0, buffer_to_arraybuffer_1.default)(stubKeyDer), rsaAlgorithmOptions, true, ['sign']);
    });
    test('derDeserializeRSAPrivateKey should default to RSA-PSS with SHA-256', async () => {
        mockImportKey.mockResolvedValueOnce(stubKeyPair.privateKey);
        const privateKey = await (0, keys_1.derDeserializeRSAPrivateKey)(stubKeyDer);
        expect(privateKey).toBe(stubKeyPair.privateKey);
        expect(mockImportKey).toBeCalledTimes(1);
        expect(mockImportKey).toBeCalledWith('pkcs8', (0, buffer_to_arraybuffer_1.default)(stubKeyDer), rsaAlgorithmOptions, true, ['sign']);
    });
    test('derDeserializeECDHPublicKey should convert DER public key to ECDH key', async () => {
        mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);
        const publicKey = await (0, keys_1.derDeserializeECDHPublicKey)(stubKeyDer, ecdhCurveName);
        expect(publicKey).toBe(stubKeyPair.publicKey);
        expect(mockImportKey).toBeCalledTimes(1);
        expect(mockImportKey).toBeCalledWith('spki', (0, buffer_to_arraybuffer_1.default)(stubKeyDer), { name: 'ECDH', namedCurve: ecdhCurveName }, true, []);
    });
    test('derDeserializeECDHPublicKey should default to P-256', async () => {
        mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);
        await (0, keys_1.derDeserializeECDHPublicKey)(stubKeyDer);
        expect(mockImportKey).toBeCalledTimes(1);
        const algorithm = mockImportKey.mock.calls[0][2];
        expect(algorithm).toHaveProperty('namedCurve', 'P-256');
    });
    test('derDeserializeECDHPublicKey should accept an ArrayBuffer serialization', async () => {
        mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);
        const publicKeyDerArrayBuffer = (0, buffer_to_arraybuffer_1.default)(stubKeyDer);
        const publicKey = await (0, keys_1.derDeserializeECDHPublicKey)(publicKeyDerArrayBuffer, ecdhCurveName);
        expect(publicKey).toBe(stubKeyPair.publicKey);
        expect(mockImportKey).toBeCalledTimes(1);
        expect(mockImportKey).toBeCalledWith('spki', publicKeyDerArrayBuffer, { name: 'ECDH', namedCurve: ecdhCurveName }, true, []);
    });
    test('derDeserializeECDHPrivateKey should convert DER private key to ECDH key', async () => {
        mockImportKey.mockResolvedValueOnce(stubKeyPair.privateKey);
        const privateKey = await (0, keys_1.derDeserializeECDHPrivateKey)(stubKeyDer, ecdhCurveName);
        expect(privateKey).toBe(stubKeyPair.privateKey);
        expect(mockImportKey).toBeCalledTimes(1);
        expect(mockImportKey).toBeCalledWith('pkcs8', (0, buffer_to_arraybuffer_1.default)(stubKeyDer), { name: 'ECDH', namedCurve: ecdhCurveName }, true, ['deriveBits', 'deriveKey']);
    });
    test('derDeserializeECDHPrivateKey should default to P-256', async () => {
        mockImportKey.mockResolvedValueOnce(stubKeyPair.privateKey);
        await (0, keys_1.derDeserializeECDHPrivateKey)(stubKeyDer);
        expect(mockImportKey).toBeCalledTimes(1);
        const algorithm = mockImportKey.mock.calls[0][2];
        expect(algorithm).toHaveProperty('namedCurve', 'P-256');
    });
});
test('getPublicKeyDigest should return the SHA-256 digest of the public key', async () => {
    const keyPair = await (0, keys_1.generateRSAKeyPair)();
    const digest = await (0, keys_1.getPublicKeyDigest)(keyPair.publicKey);
    expect(Buffer.from(digest)).toEqual((0, crypto_1.createHash)('sha256')
        .update(await (0, keys_1.derSerializePublicKey)(keyPair.publicKey))
        .digest());
});
test('getPublicKeyDigest should return the SHA-256 hex digest of the public key', async () => {
    const keyPair = await (0, keys_1.generateRSAKeyPair)();
    const digestHex = await (0, keys_1.getPublicKeyDigestHex)(keyPair.publicKey);
    expect(digestHex).toEqual((0, _test_utils_1.sha256Hex)(await (0, keys_1.derSerializePublicKey)(keyPair.publicKey)));
});
describe('getPrivateAddressFromIdentityKey', () => {
    test('Private address should be computed from identity key', async () => {
        const keyPair = await (0, keys_1.generateRSAKeyPair)();
        const privateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(keyPair.publicKey);
        expect(privateAddress).toEqual('0' + (0, _test_utils_1.sha256Hex)(await (0, keys_1.derSerializePublicKey)(keyPair.publicKey)));
    });
    test('DH keys should be refused', async () => {
        const keyPair = await (0, keys_1.generateECDHKeyPair)();
        await expect((0, keys_1.getPrivateAddressFromIdentityKey)(keyPair.publicKey)).rejects.toThrowWithMessage(Error, 'Only RSA keys are supported (got ECDH)');
    });
});
//# sourceMappingURL=keys.spec.js.map