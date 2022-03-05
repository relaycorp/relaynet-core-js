import { CertificateStore } from './CertificateStore';
import { PrivateKeyStore } from './privateKeyStore';
import { PublicKeyStore } from './publicKeyStore';

export interface KeyStoreSet {
  readonly privateKeyStore: PrivateKeyStore;
  readonly publicKeyStore: PublicKeyStore;
  readonly certificateStore: CertificateStore;
}
