import { EncryptionOptions, SignatureOptions } from '../..';
import { PrivateKeyStore } from '../privateKeyStore';

export interface CurrentNodeKeyIds {
  readonly longTermKeyId: Buffer;
  readonly initialSessionKeyId: Buffer;
}

export interface CryptoOptions {
  readonly encryptionOptions: EncryptionOptions;
  readonly signatureOptions: SignatureOptions;
}

export abstract class BaseNode {
  constructor(
    protected keyStore: PrivateKeyStore,
    protected cryptoOptions: Partial<CryptoOptions> = {},
  ) {}
}
