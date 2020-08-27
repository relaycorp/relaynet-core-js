import { OctetString, verifySchema } from 'asn1js';
import { makeSequenceSchema, serializeSequence } from '../../../asn1';
import Certificate from '../../../crypto_wrappers/x509/Certificate';
import InvalidMessageError from '../../InvalidMessageError';

export class ClientRegistration {
  public static deserialize(serialization: ArrayBuffer): ClientRegistration {
    const result = verifySchema(serialization, ClientRegistration.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Serialization is not a valid ClientRegistration');
    }

    const registrationASN1 = (result.result as any).ClientRegistration;

    // tslint:disable-next-line:no-let
    let clientCertificate: Certificate;
    try {
      clientCertificate = Certificate.deserialize(
        registrationASN1.clientCertificate.valueBlock.valueHex,
      );
    } catch (exc) {
      throw new InvalidMessageError(exc, 'Client certificate is invalid');
    }

    // tslint:disable-next-line:no-let
    let serverCertificate: Certificate;
    try {
      serverCertificate = Certificate.deserialize(
        registrationASN1.serverCertificate.valueBlock.valueHex,
      );
    } catch (exc) {
      throw new InvalidMessageError(exc, 'Server certificate is invalid');
    }
    return new ClientRegistration(clientCertificate, serverCertificate);
  }

  private static readonly SCHEMA = makeSequenceSchema('ClientRegistration', [
    'clientCertificate',
    'serverCertificate',
  ]);

  constructor(
    public readonly clientCertificate: Certificate,
    public readonly serverCertificate: Certificate,
  ) {}

  public serialize(): ArrayBuffer {
    return serializeSequence(
      new OctetString({ valueHex: this.clientCertificate.serialize() }),
      new OctetString({ valueHex: this.serverCertificate.serialize() }),
    );
  }
}
