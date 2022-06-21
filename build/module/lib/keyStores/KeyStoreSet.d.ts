import { CertificateStore } from './CertificateStore';
import { PrivateKeyStore } from './PrivateKeyStore';
import { PublicKeyStore } from './PublicKeyStore';
export interface KeyStoreSet {
    readonly privateKeyStore: PrivateKeyStore;
    readonly publicKeyStore: PublicKeyStore;
    readonly certificateStore: CertificateStore;
}
