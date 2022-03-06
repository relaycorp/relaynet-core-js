import { CertificateStore } from './CertificateStore';
import { PrivateKeyStore } from './privateKeyStore';
import { PublicKeyStore } from './PublicKeyStore';

export interface KeyStoreSet {
  readonly privateKeyStore: PrivateKeyStore;
  readonly publicKeyStore: PublicKeyStore;
  readonly certificateStore: CertificateStore;
}
