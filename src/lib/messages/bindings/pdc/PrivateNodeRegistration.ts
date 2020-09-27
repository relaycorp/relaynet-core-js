import { OctetString, Primitive, verifySchema } from 'asn1js';
import { derSerializeHeterogeneousSequence, makeHeterogeneousSequenceSchema } from '../../../asn1';
import Certificate from '../../../crypto_wrappers/x509/Certificate';
import InvalidMessageError from '../../InvalidMessageError';

export class PrivateNodeRegistration {
  public static deserialize(serialization: ArrayBuffer): PrivateNodeRegistration {
    const result = verifySchema(serialization, PrivateNodeRegistration.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Serialization is not a valid PrivateNodeRegistration');
    }

    const registrationASN1 = (result.result as any).PrivateNodeRegistration;

    // tslint:disable-next-line:no-let
    let privateNodeCertificate: Certificate;
    try {
      privateNodeCertificate = Certificate.deserialize(
        registrationASN1.privateNodeCertificate.valueBlock.valueHex,
      );
    } catch (exc) {
      throw new InvalidMessageError(exc, 'Private node certificate is invalid');
    }

    // tslint:disable-next-line:no-let
    let gatewayCertificate: Certificate;
    try {
      gatewayCertificate = Certificate.deserialize(
        registrationASN1.gatewayCertificate.valueBlock.valueHex,
      );
    } catch (exc) {
      throw new InvalidMessageError(exc, 'Gateway certificate is invalid');
    }
    return new PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate);
  }

  private static readonly SCHEMA = makeHeterogeneousSequenceSchema('PrivateNodeRegistration', [
    new Primitive({ name: 'privateNodeCertificate' }),
    new Primitive({ name: 'gatewayCertificate' }),
  ]);

  constructor(
    public readonly privateNodeCertificate: Certificate,
    public readonly gatewayCertificate: Certificate,
  ) {}

  public serialize(): ArrayBuffer {
    return derSerializeHeterogeneousSequence(
      new OctetString({ valueHex: this.privateNodeCertificate.serialize() }),
      new OctetString({ valueHex: this.gatewayCertificate.serialize() }),
    );
  }
}
