import { OctetString, verifySchema } from 'asn1js';
import { makeSequenceSchema, serializeSequence } from '../../../asn1';
import Certificate from '../../../crypto_wrappers/x509/Certificate';
import InvalidMessageError from '../../InvalidMessageError';

export class PrivateNodeRegistration {
  private static readonly SCHEMA = makeSequenceSchema('PrivateNodeRegistration', [
    'privateNodeCertificate',
    'gatewayCertificate',
  ]);

  constructor(
    public readonly privateNodeCertificate: Certificate,
    public readonly gatewayCertificate: Certificate,
  ) {
  }

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

  public serialize(): ArrayBuffer {
    return serializeSequence(
      new OctetString({ valueHex: this.privateNodeCertificate.serialize() }),
      new OctetString({ valueHex: this.gatewayCertificate.serialize() }),
    );
  }
}
