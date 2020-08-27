import { DateTime, ObjectIdentifier, OctetString, verifySchema } from 'asn1js';

import {
  asn1DateTimeToDate,
  dateToASN1DateTimeInUTC,
  makeSequenceSchema,
  serializeSequence,
} from '../../../asn1';
import { sign, verify } from '../../../crypto_wrappers/rsaSigning';
import { CRA } from '../../../oids';
import InvalidMessageError from '../../InvalidMessageError';

export class ClientRegistrationAuthorization {
  public static async deserialize(
    serialization: ArrayBuffer,
    serverPublicKey: CryptoKey,
  ): Promise<ClientRegistrationAuthorization> {
    const result = verifySchema(serialization, ClientRegistrationAuthorization.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Serialization is not a valid ClientRegistrationAuthorization');
    }

    const craASN1 = (result.result as any).ClientRegistrationAuthorization;

    const expiryDate = asn1DateTimeToDate(craASN1.expiryDate);
    if (expiryDate < new Date()) {
      throw new InvalidMessageError('CRA already expired');
    }

    const expectedSignaturePlaintext = ClientRegistrationAuthorization.makeSignaturePlaintext(
      craASN1.expiryDate,
      craASN1.serverData,
    );
    const isSignatureValid = await verify(
      craASN1.signature.valueBlock.valueHex,
      serverPublicKey,
      expectedSignaturePlaintext,
    );
    if (!isSignatureValid) {
      throw new InvalidMessageError('CRA signature is invalid');
    }

    const serverData = craASN1.serverData.valueBlock.valueHex;
    return new ClientRegistrationAuthorization(expiryDate, serverData);
  }

  private static readonly SCHEMA = makeSequenceSchema('ClientRegistrationAuthorization', [
    'expiryDate',
    'serverData',
    'signature',
  ]);

  private static makeSignaturePlaintext(
    expiryDateASN1: DateTime,
    serverDataASN1: OctetString,
  ): ArrayBuffer {
    return serializeSequence(new ObjectIdentifier({ value: CRA }), expiryDateASN1, serverDataASN1);
  }

  constructor(public readonly expiryDate: Date, public readonly serverData: ArrayBuffer) {}

  public async serialize(serverPrivateKey: CryptoKey): Promise<ArrayBuffer> {
    const expiryDateASN1 = dateToASN1DateTimeInUTC(this.expiryDate);
    const serverDataASN1 = new OctetString({ valueHex: this.serverData });
    const signaturePlaintext = ClientRegistrationAuthorization.makeSignaturePlaintext(
      expiryDateASN1,
      serverDataASN1,
    );
    const signature = await sign(signaturePlaintext, serverPrivateKey);
    return serializeSequence(
      expiryDateASN1,
      serverDataASN1,
      new OctetString({ valueHex: signature }),
    );
  }
}
