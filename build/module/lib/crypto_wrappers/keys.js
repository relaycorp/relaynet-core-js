import bufferToArray from 'buffer-to-arraybuffer';
import { getAlgorithmParameters } from 'pkijs';
import { getPkijsCrypto } from './_utils';
const cryptoEngine = getPkijsCrypto();
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
export async function generateRSAKeyPair(options = {}) {
    const modulus = options.modulus ?? 2048;
    if (modulus < 2048) {
        throw new Error(`RSA modulus must be => 2048 per RS-018 (got ${modulus})`);
    }
    const hashingAlgorithm = options.hashingAlgorithm ?? 'SHA-256';
    // RS-018 disallows MD5 and SHA-1, but only SHA-1 is supported in WebCrypto
    if (hashingAlgorithm === 'SHA-1') {
        throw new Error('SHA-1 is disallowed by RS-018');
    }
    const algorithm = getAlgorithmParameters('RSA-PSS', 'generateKey');
    const rsaAlgorithm = algorithm.algorithm;
    // tslint:disable-next-line:no-object-mutation
    rsaAlgorithm.hash.name = hashingAlgorithm;
    // tslint:disable-next-line:no-object-mutation
    rsaAlgorithm.modulusLength = modulus;
    const keyPair = await cryptoEngine.generateKey(rsaAlgorithm, true, algorithm.usages);
    return keyPair;
}
/**
 * Generate ECDH key pair.
 *
 * @param curveName
 */
export async function generateECDHKeyPair(curveName = 'P-256') {
    return cryptoEngine.generateKey({ name: 'ECDH', namedCurve: curveName }, true, [
        'deriveBits',
        'deriveKey',
    ]);
}
export async function getRSAPublicKeyFromPrivate(privateKey) {
    const publicKeyDer = await cryptoEngine.exportKey('spki', privateKey);
    const hashingAlgoName = privateKey.algorithm.hash.name;
    const opts = { hash: { name: hashingAlgoName }, name: privateKey.algorithm.name };
    return cryptoEngine.importKey('spki', publicKeyDer, opts, true, ['verify']);
}
//endregion
//region Key serialization
/**
 * Return DER serialization of public key.
 *
 * @param publicKey
 */
export async function derSerializePublicKey(publicKey) {
    const publicKeyDer = await cryptoEngine.exportKey('spki', publicKey);
    return Buffer.from(publicKeyDer);
}
/**
 * Return DER serialization of private key.
 *
 * @param privateKey
 */
export async function derSerializePrivateKey(privateKey) {
    const keyDer = (await cryptoEngine.exportKey('pkcs8', privateKey));
    return Buffer.from(keyDer);
}
//endregion
//region key deserialization
/**
 * Parse DER-serialized RSA public key.
 *
 * @param publicKeyDer
 * @param algorithmOptions
 */
export async function derDeserializeRSAPublicKey(publicKeyDer, algorithmOptions = DEFAULT_RSA_KEY_PARAMS) {
    const keyData = publicKeyDer instanceof Buffer ? bufferToArray(publicKeyDer) : publicKeyDer;
    return cryptoEngine.importKey('spki', keyData, algorithmOptions, true, ['verify']);
}
/**
 * Parse DER-serialized ECDH public key.
 *
 * @param publicKeyDer
 * @param curveName
 */
export async function derDeserializeECDHPublicKey(publicKeyDer, curveName = 'P-256') {
    const keyData = publicKeyDer instanceof Buffer ? bufferToArray(publicKeyDer) : publicKeyDer;
    return cryptoEngine.importKey('spki', keyData, { name: 'ECDH', namedCurve: curveName }, true, []);
}
/**
 * Parse DER-serialized RSA private key.
 *
 * @param privateKeyDer
 * @param algorithmOptions
 */
export async function derDeserializeRSAPrivateKey(privateKeyDer, algorithmOptions = DEFAULT_RSA_KEY_PARAMS) {
    return cryptoEngine.importKey('pkcs8', bufferToArray(privateKeyDer), algorithmOptions, true, [
        'sign',
    ]);
}
/**
 * Parse DER-serialized ECDH private key.
 *
 * @param privateKeyDer
 * @param curveName
 */
export async function derDeserializeECDHPrivateKey(privateKeyDer, curveName = 'P-256') {
    return cryptoEngine.importKey('pkcs8', bufferToArray(privateKeyDer), { name: 'ECDH', namedCurve: curveName }, true, ['deriveBits', 'deriveKey']);
}
//endregion
/**
 * Return SHA-256 digest of public key.
 *
 * @param publicKey
 */
export async function getPublicKeyDigest(publicKey) {
    const publicKeyDer = await cryptoEngine.exportKey('spki', publicKey);
    return cryptoEngine.digest({ name: 'SHA-256' }, publicKeyDer);
}
/**
 * Return hexadecimal, SHA-256 digest of public key.
 *
 * @param publicKey
 */
export async function getPublicKeyDigestHex(publicKey) {
    const digest = Buffer.from(await getPublicKeyDigest(publicKey));
    return digest.toString('hex');
}
export async function getPrivateAddressFromIdentityKey(identityPublicKey) {
    const algorithmName = identityPublicKey.algorithm.name;
    if (!algorithmName.startsWith('RSA-')) {
        throw new Error(`Only RSA keys are supported (got ${algorithmName})`);
    }
    const keyDigest = await getPublicKeyDigestHex(identityPublicKey);
    return `0${keyDigest}`;
}
//# sourceMappingURL=keys.js.map