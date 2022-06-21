/// <reference types="node" />
import { ECDHCurveName, HashingAlgorithm, RSAModulus } from './algorithms';
export interface RSAKeyGenOptions {
    readonly modulus: RSAModulus;
    readonly hashingAlgorithm: HashingAlgorithm;
}
/**
 * Generate an RSA-PSS key pair.
 *
 * @param options The RSA key generation options
 * @throws Error If the modulus or the hashing algorithm is disallowed by RS-018.
 */
export declare function generateRSAKeyPair(options?: Partial<RSAKeyGenOptions>): Promise<CryptoKeyPair>;
/**
 * Generate ECDH key pair.
 *
 * @param curveName
 */
export declare function generateECDHKeyPair(curveName?: ECDHCurveName): Promise<CryptoKeyPair>;
export declare function getRSAPublicKeyFromPrivate(privateKey: CryptoKey): Promise<CryptoKey>;
/**
 * Return DER serialization of public key.
 *
 * @param publicKey
 */
export declare function derSerializePublicKey(publicKey: CryptoKey): Promise<Buffer>;
/**
 * Return DER serialization of private key.
 *
 * @param privateKey
 */
export declare function derSerializePrivateKey(privateKey: CryptoKey): Promise<Buffer>;
/**
 * Parse DER-serialized RSA public key.
 *
 * @param publicKeyDer
 * @param algorithmOptions
 */
export declare function derDeserializeRSAPublicKey(publicKeyDer: Buffer | ArrayBuffer, algorithmOptions?: RsaHashedImportParams): Promise<CryptoKey>;
/**
 * Parse DER-serialized ECDH public key.
 *
 * @param publicKeyDer
 * @param curveName
 */
export declare function derDeserializeECDHPublicKey(publicKeyDer: Buffer | ArrayBuffer, curveName?: NamedCurve): Promise<CryptoKey>;
/**
 * Parse DER-serialized RSA private key.
 *
 * @param privateKeyDer
 * @param algorithmOptions
 */
export declare function derDeserializeRSAPrivateKey(privateKeyDer: Buffer, algorithmOptions?: RsaHashedImportParams): Promise<CryptoKey>;
/**
 * Parse DER-serialized ECDH private key.
 *
 * @param privateKeyDer
 * @param curveName
 */
export declare function derDeserializeECDHPrivateKey(privateKeyDer: Buffer, curveName?: NamedCurve): Promise<CryptoKey>;
/**
 * Return SHA-256 digest of public key.
 *
 * @param publicKey
 */
export declare function getPublicKeyDigest(publicKey: CryptoKey): Promise<ArrayBuffer>;
/**
 * Return hexadecimal, SHA-256 digest of public key.
 *
 * @param publicKey
 */
export declare function getPublicKeyDigestHex(publicKey: CryptoKey): Promise<string>;
export declare function getPrivateAddressFromIdentityKey(identityPublicKey: CryptoKey): Promise<string>;
