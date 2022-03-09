// tslint:disable:max-classes-per-file

import { SignedData } from '../../crypto_wrappers/cms/signedData';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { makeSafePlaintext } from './utils';

// noinspection TypeScriptAbstractClassConstructorCanBeMadeProtected
/**
 * Object to verify detached signatures given a key pair.
 */
export abstract class Verifier {
  /**
   * @internal
   */
  public abstract readonly oid: string;

  constructor(protected trustedCertificates: readonly Certificate[]) {}

  /**
   * Verify `signatureSerialized` and return the signer's certificate if valid.
   *
   * @param signatureSerialized
   * @param expectedPlaintext
   * @throws CMSError if the signatureSerialized is invalid
   * @throws CertificateError if the signer isn't trusted
   */
  public async verify(
    signatureSerialized: ArrayBuffer,
    expectedPlaintext: ArrayBuffer,
  ): Promise<Certificate> {
    const signedData = SignedData.deserialize(signatureSerialized);
    const safePlaintext = makeSafePlaintext(expectedPlaintext, this.oid);
    await signedData.verify(safePlaintext);

    const signerCertificate = signedData.signerCertificate!!;
    await signerCertificate.getCertificationPath([], this.trustedCertificates);
    return signerCertificate;
  }
}
