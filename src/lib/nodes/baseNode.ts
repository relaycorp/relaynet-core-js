import { EncryptionOptions } from '../crypto_wrappers/cms/envelopedData';
import { SignatureOptions } from '../crypto_wrappers/cms/signedData';
import { PrivateKeyStore } from '../keyStores/privateKeyStore';

export interface CurrentNodeKeyIds {
  readonly longTermKeyId: Buffer;
  readonly initialSessionKeyId: Buffer;
}

export interface NodeOptions {
  readonly encryption: EncryptionOptions;
  readonly signature: SignatureOptions;
}

export abstract class BaseNode {
  constructor(
    protected keyStore: PrivateKeyStore,
    protected cryptoOptions: Partial<NodeOptions> = {},
  ) {}
}
