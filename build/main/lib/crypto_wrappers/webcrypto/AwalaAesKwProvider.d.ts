import { AesKwProvider, CryptoKey } from 'webcrypto-core';
/**
 * AES-KW provider that uses pure JavaScript for encryption and decryption.
 */
export declare class AwalaAesKwProvider extends AesKwProvider {
    protected readonly originalProvider: AesKwProvider;
    constructor(originalProvider: AesKwProvider);
    onGenerateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
    onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer>;
    onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
    onEncrypt(_algorithm: Algorithm, key: any, data: ArrayBuffer): Promise<ArrayBuffer>;
    onDecrypt(_algorithm: Algorithm, key: any, data: ArrayBuffer): Promise<ArrayBuffer>;
    private makeAesKw;
}
