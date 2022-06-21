"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPrivateAddressFromIdentityKey = exports.getPublicKeyDigestHex = exports.getPublicKeyDigest = exports.derDeserializeECDHPrivateKey = exports.derDeserializeRSAPrivateKey = exports.derDeserializeECDHPublicKey = exports.derDeserializeRSAPublicKey = exports.derSerializePrivateKey = exports.derSerializePublicKey = exports.getRSAPublicKeyFromPrivate = exports.generateECDHKeyPair = exports.generateRSAKeyPair = void 0;
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const pkijs_1 = require("pkijs");
const _utils_1 = require("./_utils");
const cryptoEngine = (0, _utils_1.getPkijsCrypto)();
const DEFAULT_RSA_KEY_PARAMS = {
    hash: { name: 'SHA-256' },
    name: 'RSA-PSS',
};
/**
 * Generate an RSA-PSS key pair.
 *
 * @param options The RSA key generation options
 * @throws Error If the modulus or the hashing algorithm is disallowed by RS-018.
 */
async function generateRSAKeyPair(options = {}) {
    const modulus = options.modulus ?? 2048;
    if (modulus < 2048) {
        throw new Error(`RSA modulus must be => 2048 per RS-018 (got ${modulus})`);
    }
    const hashingAlgorithm = options.hashingAlgorithm ?? 'SHA-256';
    // RS-018 disallows MD5 and SHA-1, but only SHA-1 is supported in WebCrypto
    if (hashingAlgorithm === 'SHA-1') {
        throw new Error('SHA-1 is disallowed by RS-018');
    }
    const algorithm = (0, pkijs_1.getAlgorithmParameters)('RSA-PSS', 'generateKey');
    const rsaAlgorithm = algorithm.algorithm;
    // tslint:disable-next-line:no-object-mutation
    rsaAlgorithm.hash.name = hashingAlgorithm;
    // tslint:disable-next-line:no-object-mutation
    rsaAlgorithm.modulusLength = modulus;
    const keyPair = await cryptoEngine.generateKey(rsaAlgorithm, true, algorithm.usages);
    return keyPair;
}
exports.generateRSAKeyPair = generateRSAKeyPair;
/**
 * Generate ECDH key pair.
 *
 * @param curveName
 */
async function generateECDHKeyPair(curveName = 'P-256') {
    return cryptoEngine.generateKey({ name: 'ECDH', namedCurve: curveName }, true, [
        'deriveBits',
        'deriveKey',
    ]);
}
exports.generateECDHKeyPair = generateECDHKeyPair;
async function getRSAPublicKeyFromPrivate(privateKey) {
    const publicKeyDer = await cryptoEngine.exportKey('spki', privateKey);
    const hashingAlgoName = privateKey.algorithm.hash.name;
    const opts = { hash: { name: hashingAlgoName }, name: privateKey.algorithm.name };
    return cryptoEngine.importKey('spki', publicKeyDer, opts, true, ['verify']);
}
exports.getRSAPublicKeyFromPrivate = getRSAPublicKeyFromPrivate;
//endregion
//region Key serialization
/**
 * Return DER serialization of public key.
 *
 * @param publicKey
 */
async function derSerializePublicKey(publicKey) {
    const publicKeyDer = await cryptoEngine.exportKey('spki', publicKey);
    return Buffer.from(publicKeyDer);
}
exports.derSerializePublicKey = derSerializePublicKey;
/**
 * Return DER serialization of private key.
 *
 * @param privateKey
 */
async function derSerializePrivateKey(privateKey) {
    const keyDer = (await cryptoEngine.exportKey('pkcs8', privateKey));
    return Buffer.from(keyDer);
}
exports.derSerializePrivateKey = derSerializePrivateKey;
//endregion
//region key deserialization
/**
 * Parse DER-serialized RSA public key.
 *
 * @param publicKeyDer
 * @param algorithmOptions
 */
async function derDeserializeRSAPublicKey(publicKeyDer, algorithmOptions = DEFAULT_RSA_KEY_PARAMS) {
    const keyData = publicKeyDer instanceof Buffer ? (0, buffer_to_arraybuffer_1.default)(publicKeyDer) : publicKeyDer;
    return cryptoEngine.importKey('spki', keyData, algorithmOptions, true, ['verify']);
}
exports.derDeserializeRSAPublicKey = derDeserializeRSAPublicKey;
/**
 * Parse DER-serialized ECDH public key.
 *
 * @param publicKeyDer
 * @param curveName
 */
async function derDeserializeECDHPublicKey(publicKeyDer, curveName = 'P-256') {
    const keyData = publicKeyDer instanceof Buffer ? (0, buffer_to_arraybuffer_1.default)(publicKeyDer) : publicKeyDer;
    return cryptoEngine.importKey('spki', keyData, { name: 'ECDH', namedCurve: curveName }, true, []);
}
exports.derDeserializeECDHPublicKey = derDeserializeECDHPublicKey;
/**
 * Parse DER-serialized RSA private key.
 *
 * @param privateKeyDer
 * @param algorithmOptions
 */
async function derDeserializeRSAPrivateKey(privateKeyDer, algorithmOptions = DEFAULT_RSA_KEY_PARAMS) {
    return cryptoEngine.importKey('pkcs8', (0, buffer_to_arraybuffer_1.default)(privateKeyDer), algorithmOptions, true, [
        'sign',
    ]);
}
exports.derDeserializeRSAPrivateKey = derDeserializeRSAPrivateKey;
/**
 * Parse DER-serialized ECDH private key.
 *
 * @param privateKeyDer
 * @param curveName
 */
async function derDeserializeECDHPrivateKey(privateKeyDer, curveName = 'P-256') {
    return cryptoEngine.importKey('pkcs8', (0, buffer_to_arraybuffer_1.default)(privateKeyDer), { name: 'ECDH', namedCurve: curveName }, true, ['deriveBits', 'deriveKey']);
}
exports.derDeserializeECDHPrivateKey = derDeserializeECDHPrivateKey;
//endregion
/**
 * Return SHA-256 digest of public key.
 *
 * @param publicKey
 */
async function getPublicKeyDigest(publicKey) {
    const publicKeyDer = await cryptoEngine.exportKey('spki', publicKey);
    return cryptoEngine.digest({ name: 'SHA-256' }, publicKeyDer);
}
exports.getPublicKeyDigest = getPublicKeyDigest;
/**
 * Return hexadecimal, SHA-256 digest of public key.
 *
 * @param publicKey
 */
async function getPublicKeyDigestHex(publicKey) {
    const digest = Buffer.from(await getPublicKeyDigest(publicKey));
    return digest.toString('hex');
}
exports.getPublicKeyDigestHex = getPublicKeyDigestHex;
async function getPrivateAddressFromIdentityKey(identityPublicKey) {
    const algorithmName = identityPublicKey.algorithm.name;
    if (!algorithmName.startsWith('RSA-')) {
        throw new Error(`Only RSA keys are supported (got ${algorithmName})`);
    }
    const keyDigest = await getPublicKeyDigestHex(identityPublicKey);
    return `0${keyDigest}`;
}
exports.getPrivateAddressFromIdentityKey = getPrivateAddressFromIdentityKey;
//# sourceMappingURL=keys.js.map