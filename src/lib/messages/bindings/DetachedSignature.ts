import { ObjectIdentifier, OctetString } from 'asn1js';
import { derSerializeHeterogeneousSequence } from '../../asn1';
import { SignedData } from '../../crypto_wrappers/cms/signedData';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { RELAYNET_OIDS } from '../../oids';

/**
 * Utility to sign and verify CMS SignedData values where the plaintext is not encapsulated (to
 * avoid re-encoding the plaintext for performance reasons), and the signer's certificate is
 * encapsulated.
 */
export class DetachedSignature {
  constructor(public oid: string) {}

  /**
   * Sign the `plaintext` and return the CMS SignedData serialized.
   *
   * @param plaintext
   * @param privateKey
   * @param signerCertificate
   */
  public async sign(
    plaintext: ArrayBuffer,
    privateKey: CryptoKey,
    signerCertificate: Certificate,
  ): Promise<ArrayBuffer> {
    const safePlaintext = this.makeSafePlaintext(plaintext);
    const signedData = await SignedData.sign(safePlaintext, privateKey, signerCertificate, [], {
      encapsulatePlaintext: false,
    });
    return signedData.serialize();
  }

  /**
   * Verify `signatureSerialized` and return the signer's certificate if valid.
   *
   * @param signatureSerialized
   * @param expectedPlaintext
   * @param trustedCertificates
   * @throws CMSError if the signatureSerialized is invalid or the signer isn't trusted
   */
  public async verify(
    signatureSerialized: ArrayBuffer,
    expectedPlaintext: ArrayBuffer,
    trustedCertificates: readonly Certificate[],
  ): Promise<Certificate> {
    const signedData = SignedData.deserialize(signatureSerialized);
    const safePlaintext = this.makeSafePlaintext(expectedPlaintext);
    await signedData.verify(safePlaintext, trustedCertificates);
    return signedData.signerCertificate!!;
  }

  protected makeSafePlaintext(plaintext: ArrayBuffer): ArrayBuffer {
    return derSerializeHeterogeneousSequence(
      new ObjectIdentifier({ value: this.oid }),
      new OctetString({ valueHex: plaintext }),
    );
  }
}

export const PARCEL_DELIVERY = new DetachedSignature(RELAYNET_OIDS.SIGNATURE.PARCEL_DELIVERY);

export const NONCE_SIGNATURE = new DetachedSignature(RELAYNET_OIDS.SIGNATURE.NONCE);
