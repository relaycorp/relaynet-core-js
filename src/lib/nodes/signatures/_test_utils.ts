// tslint:disable:max-classes-per-file

import { Certificate } from '../../crypto_wrappers/x509/Certificate';
import { Signer } from './Signer';
import { Verifier } from './Verifier';

export const STUB_OID_VALUE = '1.2.3.4';

export class StubSigner extends Signer {
  public readonly oid = STUB_OID_VALUE;
}

export class StubVerifier extends Verifier {
  public readonly oid = STUB_OID_VALUE;

  public getTrustedCertificates(): readonly Certificate[] {
    return this.trustedCertificates;
  }
}
