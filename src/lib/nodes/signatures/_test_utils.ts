import { Signer } from './Signer';

export const STUB_OID_VALUE = '1.2.3.4';

export class StubSigner extends Signer {
  public readonly oid = STUB_OID_VALUE;
}
