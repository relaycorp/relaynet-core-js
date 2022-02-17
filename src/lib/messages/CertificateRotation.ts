import { Constructed, OctetString, Primitive, verifySchema } from 'asn1js';

import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../asn1';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { generateFormatSignature } from './formatSignature';
import InvalidMessageError from './InvalidMessageError';

export const CERTIFICATE_ROTATION_FORMAT_SIGNATURE = generateFormatSignature(0x10, 0);

export class CertificateRotation {
  public static deserialize(serialization: ArrayBuffer): CertificateRotation {
    const formatSignature = Buffer.from(
      serialization.slice(0, CERTIFICATE_ROTATION_FORMAT_SIGNATURE.byteLength),
    );
    if (!formatSignature.equals(CERTIFICATE_ROTATION_FORMAT_SIGNATURE)) {
      throw new InvalidMessageError('Format signature should be that of a CertificateRotation');
    }

    const sequenceSerialized = serialization.slice(formatSignature.byteLength);
    const result = verifySchema(sequenceSerialized, CertificateRotation.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError(
        'Serialization did not meet structure of a CertificateRotation',
      );
    }

    const rotationBlock = (result.result as any).CertificateRotation;

    let subjectCertificate: Certificate;
    try {
      subjectCertificate = Certificate.deserialize(
        rotationBlock.subjectCertificate.valueBlock.valueHex,
      );
    } catch (err) {
      throw new InvalidMessageError('Subject certificate is malformed');
    }

    let chain: readonly Certificate[];
    const chainCertsSerialized: readonly ArrayBuffer[] = rotationBlock.chain.valueBlock.value.map(
      (c: Primitive) => c.valueBlock.valueHex,
    );
    try {
      chain = chainCertsSerialized.map((c) => Certificate.deserialize(c));
    } catch (err) {
      throw new InvalidMessageError('Chain contains malformed certificate');
    }

    return new CertificateRotation(subjectCertificate, chain);
  }

  private static readonly SCHEMA = makeHeterogeneousSequenceSchema('CertificateRotation', [
    new Primitive({ name: 'subjectCertificate' }),
    new Constructed({ name: 'chain' }),
  ]);

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
      CERTIFICATE_ROTATION_FORMAT_SIGNATURE.byteLength + sequenceSerialized.byteLength,
    );
    const serializationView = new Uint8Array(serialization);
    serializationView.set(CERTIFICATE_ROTATION_FORMAT_SIGNATURE, 0);
    serializationView.set(
      new Uint8Array(sequenceSerialized),
      CERTIFICATE_ROTATION_FORMAT_SIGNATURE.byteLength,
    );
    return serialization;
  }
}
