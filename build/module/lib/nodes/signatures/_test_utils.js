// tslint:disable:max-classes-per-file
import { Signer } from './Signer';
import { Verifier } from './Verifier';
export const STUB_OID_VALUE = '1.2.3.4';
export class StubSigner extends Signer {
    oid = STUB_OID_VALUE;
}
export class StubVerifier extends Verifier {
    oid = STUB_OID_VALUE;
    getTrustedCertificates() {
        return this.trustedCertificates;
    }
}
//# sourceMappingURL=_test_utils.js.map