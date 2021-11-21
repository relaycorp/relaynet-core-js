import { AesKwProvider as IAesKwProvider, CryptoKey } from 'webcrypto-core';

export class AesKwProvider extends IAesKwProvider {
  constructor(protected readonly originalProvider: IAesKwProvider) {
    super();
  }

  public async onGenerateKey(
    algorithm: AesKeyGenParams,
    extractable: boolean,
    // tslint:disable-next-line:readonly-array
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey> {
    return this.originalProvider.onGenerateKey(algorithm, extractable, keyUsages);
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return this.originalProvider.onExportKey(format, key);
  }

  public async onImportKey(
    format: KeyFormat,
    keyData: JsonWebKey | ArrayBuffer,
    algorithm: Algorithm,
    extractable: boolean,
    // tslint:disable-next-line:readonly-array
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey> {
    return this.originalProvider.onImportKey(format, keyData, algorithm, extractable, keyUsages);
  }
}
