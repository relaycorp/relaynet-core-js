/* tslint:disable:max-classes-per-file */

import { AesKwProvider, RsaPssProvider } from 'webcrypto-core';

export class MockAesKwProvider extends AesKwProvider {
  public override readonly onGenerateKey = jest.fn();
  public override readonly onExportKey = jest.fn();
  public override readonly onImportKey = jest.fn();
}

export class MockRsaPssProvider extends RsaPssProvider {
  public override readonly onGenerateKey = jest.fn();
  public override readonly onSign = jest.fn();
  public override readonly onVerify = jest.fn();
  public override readonly onExportKey = jest.fn();
  public override readonly onImportKey = jest.fn();
}
