import { Constructed, OctetString, Primitive, Sequence, verifySchema } from 'asn1js';

import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../asn1';
import { Certificate } from '../crypto_wrappers/x509/Certificate';
import { InvalidMessageError } from '../messages/InvalidMessageError';

export class CertificationPath {
  public static deserialize(serialization: ArrayBuffer): CertificationPath {
    const result = verifySchema(serialization, CertificationPath.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Serialization did not meet structure of a CertificationPath');
    }

    const rotationBlock = (result.result as any).CertificationPath;

    let leafCertificate: Certificate;
    try {
      leafCertificate = Certificate.deserialize(rotationBlock.leafCertificate.valueBlock.valueHex);
    } catch (err) {
      throw new InvalidMessageError('Leaf certificate is malformed');
    }

    let certificateAuthorities: readonly Certificate[];
    const casASN1 = rotationBlock.certificateAuthorities.valueBlock.value;
    const casSerialized: readonly ArrayBuffer[] = casASN1.map(
      (c: Primitive) => c.valueBlock.valueHex,
    );
    try {
      certificateAuthorities = casSerialized.map((c) => Certificate.deserialize(c));
    } catch (err) {
      throw new InvalidMessageError('Certificate authorities contain malformed certificate');
    }

    return new CertificationPath(leafCertificate, certificateAuthorities);
  }

  private static readonly SCHEMA = makeHeterogeneousSequenceSchema('CertificationPath', [
    new Primitive({ name: 'leafCertificate' }),
    new Constructed({ name: 'certificateAuthorities' }),
  ]);

  constructor(
    public readonly leafCertificate: Certificate,
    public readonly certificateAuthorities: readonly Certificate[],
  ) {}

  public serialize(): ArrayBuffer {
    const casASN1 = this.certificateAuthorities.map(
      (c) => new OctetString({ valueHex: c.serialize() }),
    );
    const sequence = makeImplicitlyTaggedSequence(
      new OctetString({ valueHex: this.leafCertificate.serialize() }),
      new Sequence({ value: casASN1 }),
    );
    return sequence.toBER();
  }
}
