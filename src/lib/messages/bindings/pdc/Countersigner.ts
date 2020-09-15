import { ObjectIdentifier, OctetString } from 'asn1js';
import { serializeSequence } from '../../../asn1';
import { SignedData } from '../../../crypto_wrappers/cms/signedData';
import Certificate from '../../../crypto_wrappers/x509/Certificate';
import { RELAYNET_OIDS } from '../../../oids';

/**
 * Utility to sign and verify countersignatures.
 *
 * Such countersignatures are represented with CMS SignedData values where the plaintext is not
 * encapsulated (to avoid re-encoding the plaintext for performance reasons), and the
 * (counter)signer's certificate is encapsulated.
 */
export class Countersigner {
  constructor(public oid: string) {}

  public async sign(
    plaintext: ArrayBuffer,
    privateKey: CryptoKey,
    signerCertificate: Certificate,
  ): Promise<ArrayBuffer> {
    const safePlaintext = this.makeSafePlaintext(plaintext);
    const signedData = await SignedData.sign(safePlaintext, privateKey, signerCertificate, [], {
      encapsulatedSignature: false,
    });
    return signedData.serialize();
  }

  public async verify(
    countersignature: ArrayBuffer,
    expectedPlaintext: ArrayBuffer,
    trustedCertificates: readonly Certificate[],
  ): Promise<void> {
    const signedData = SignedData.deserialize(countersignature);
    const safePlaintext = this.makeSafePlaintext(expectedPlaintext);
    await signedData.verify(safePlaintext, trustedCertificates);
  }

  protected makeSafePlaintext(plaintext: ArrayBuffer): ArrayBuffer {
    return serializeSequence(
      new ObjectIdentifier({ value: this.oid }),
      new OctetString({ valueHex: plaintext }),
    );
  }
}

export const PARCEL_DELIVERY = new Countersigner(RELAYNET_OIDS.COUNTERSIGNATURE.PARCEL_DELIVERY);
