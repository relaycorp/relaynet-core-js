import Certificate from '../../crypto_wrappers/x509/Certificate';
import { NONCE_SIGNATURE } from './DetachedSignature';

/**
 * Handshake nonce signer for a given private endpoint or private gateway.
 *
 */
export class NonceSigner {
  /**
   *
   * @param certificate The certificate of the private node
   * @param privateKey The private key of the private node
   */
  constructor(public certificate: Certificate, private privateKey: CryptoKey) {}

  public async sign(nonce: ArrayBuffer): Promise<ArrayBuffer> {
    return NONCE_SIGNATURE.sign(nonce, this.privateKey, this.certificate);
  }
}
