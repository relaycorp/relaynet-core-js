import { EncryptionOptions } from '../crypto_wrappers/cms/envelopedData';
import { SignatureOptions } from '../crypto_wrappers/cms/SignatureOptions';

export interface NodeCryptoOptions {
  readonly encryption: Partial<EncryptionOptions>;
  readonly signature: Partial<SignatureOptions>;
}
