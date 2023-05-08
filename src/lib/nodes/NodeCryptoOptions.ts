import { EncryptionOptions } from '../crypto/cms/envelopedData';
import { SignatureOptions } from '../crypto/cms/SignatureOptions';

export interface NodeCryptoOptions {
  readonly encryption: Partial<EncryptionOptions>;
  readonly signature: Partial<SignatureOptions>;
}
