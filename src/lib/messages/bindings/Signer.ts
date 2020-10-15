import Certificate from '../../crypto_wrappers/x509/Certificate';
import { DetachedSignatureType } from './DetachedSignatureType';

/**
 * Object to produce detached signatures given a key pair..
 *
 */
export class Signer {
  /**
   *
   * @param certificate The certificate of the private node
   * @param privateKey The private key of the private node
   */
  constructor(public certificate: Certificate, private privateKey: CryptoKey) {}

  public async sign(
    plaintext: ArrayBuffer,
    detachedSignatureType: DetachedSignatureType,
  ): Promise<ArrayBuffer> {
    return detachedSignatureType.sign(plaintext, this.privateKey, this.certificate);
  }
}
