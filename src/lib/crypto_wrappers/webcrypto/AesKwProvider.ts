import { AESKW } from '@stablelib/aes-kw';
import { AesKwProvider as BaseAesKwProvider, CryptoKey } from 'webcrypto-core';

export class AesKwProvider extends BaseAesKwProvider {
  constructor(protected readonly originalProvider: BaseAesKwProvider) {
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

  public async onEncrypt(_algorithm: Algorithm, key: any, data: ArrayBuffer): Promise<ArrayBuffer> {
    const aesKw = await this.makeAesKw(key);
    return aesKw.wrapKey(new Uint8Array(data));
  }

  public async onDecrypt(_algorithm: Algorithm, key: any, data: ArrayBuffer): Promise<ArrayBuffer> {
    const aesKw = await this.makeAesKw(key);
    return typedArrayToBuffer(aesKw.unwrapKey(new Uint8Array(data)));
  }

  private async makeAesKw(key: any): Promise<AESKW> {
    const keyExported = (await this.onExportKey('raw', key)) as ArrayBuffer;
    return new AESKW(new Uint8Array(keyExported));
  }
}

function typedArrayToBuffer(array: Uint8Array): ArrayBuffer {
  return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset);
}
