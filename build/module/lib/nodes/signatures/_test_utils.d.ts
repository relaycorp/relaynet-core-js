import Certificate from '../../crypto_wrappers/x509/Certificate';
import { Signer } from './Signer';
import { Verifier } from './Verifier';
export declare const STUB_OID_VALUE = "1.2.3.4";
export declare class StubSigner extends Signer {
    readonly oid = "1.2.3.4";
}
export declare class StubVerifier extends Verifier {
    readonly oid = "1.2.3.4";
    getTrustedCertificates(): readonly Certificate[];
}
