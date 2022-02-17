import { Constructed, OctetString } from 'asn1js';

import { makeImplicitlyTaggedSequence } from '../asn1';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { generateFormatSignature } from './formatSignature';

export class CertificateRotation {
  public static readonly FORMAT_SIGNATURE = generateFormatSignature(0x10, 0);

  constructor(
    public readonly subjectCertificate: Certificate,
    public readonly chain: readonly Certificate[],
  ) {}

  public serialize(): ArrayBuffer {
    // Serialize sequence
    const chainASN1 = this.chain.map((c) => new OctetString({ valueHex: c.serialize() }));
    const sequenceSerialized = makeImplicitlyTaggedSequence(
      new OctetString({ valueHex: this.subjectCertificate.serialize() }),
      new Constructed({ value: chainASN1 } as any),
    ).toBER();

    // Serialize entire message
    const serialization = new ArrayBuffer(
      CertificateRotation.FORMAT_SIGNATURE.byteLength + sequenceSerialized.byteLength,
    );
    const serializationView = new Uint8Array(serialization);
    serializationView.set(CertificateRotation.FORMAT_SIGNATURE, 0);
    serializationView.set(
      new Uint8Array(sequenceSerialized),
      CertificateRotation.FORMAT_SIGNATURE.byteLength,
    );
    return serialization;
  }
}
