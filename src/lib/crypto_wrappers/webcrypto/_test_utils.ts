import { AesKwProvider } from 'webcrypto-core';

export class MockAesKwProvider extends AesKwProvider {
  public readonly onGenerateKey = jest.fn();
  public readonly onExportKey = jest.fn();
  public readonly onImportKey = jest.fn();
}
