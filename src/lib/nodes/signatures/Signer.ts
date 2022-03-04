import { SignedData } from '../../crypto_wrappers/cms/signedData';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { makeSafePlaintext } from './utils';

// noinspection TypeScriptAbstractClassConstructorCanBeMadeProtected
/**
 * Object to produce detached signatures given a key pair.
 */
export abstract class Signer {
  public abstract readonly oid: string;

  /**
   *
   * @param certificate The certificate of the node
   * @param privateKey The private key of the node
   */
  constructor(public certificate: Certificate, private privateKey: CryptoKey) {}

  public async sign(plaintext: ArrayBuffer): Promise<ArrayBuffer> {
    const safePlaintext = makeSafePlaintext(plaintext, this.oid);
    const signedData = await SignedData.sign(safePlaintext, this.privateKey, this.certificate, [], {
      encapsulatePlaintext: false,
    });
    return signedData.serialize();
  }
}
