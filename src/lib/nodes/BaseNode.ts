import Certificate from '../crypto_wrappers/x509/Certificate';
import { Signer } from './signatures/Signer';

export abstract class BaseNode {
  protected constructor(public certificate: Certificate, protected privateKey: CryptoKey) {}

  public getSigner<S extends Signer>(
    signerClass: new (certificate: Certificate, privateKey: CryptoKey) => S,
  ): S {
    return new signerClass(this.certificate, this.privateKey);
  }
}
