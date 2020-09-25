import { DateTime, ObjectIdentifier, OctetString, verifySchema } from 'asn1js';

import {
  asn1DateTimeToDate,
  dateToASN1DateTimeInUTC,
  derSerializeHeterogeneousSequence,
  makeSequenceSchema,
} from '../../../asn1';
import { sign, verify } from '../../../crypto_wrappers/rsaSigning';
import { RELAYNET_OIDS } from '../../../oids';
import InvalidMessageError from '../../InvalidMessageError';

export class PrivateNodeRegistrationAuthorization {
  public static async deserialize(
    serialization: ArrayBuffer,
    gatewayPublicKey: CryptoKey,
  ): Promise<PrivateNodeRegistrationAuthorization> {
    const result = verifySchema(serialization, PrivateNodeRegistrationAuthorization.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError(
        'Serialization is not a valid PrivateNodeRegistrationAuthorization',
      );
    }

    const authorizationASN1 = (result.result as any).PrivateNodeRegistrationAuthorization;

    const expiryDate = asn1DateTimeToDate(authorizationASN1.expiryDate);
    if (expiryDate < new Date()) {
      throw new InvalidMessageError('Authorization already expired');
    }

    const expectedSignaturePlaintext = PrivateNodeRegistrationAuthorization.makeSignaturePlaintext(
      authorizationASN1.expiryDate,
      authorizationASN1.gatewayData,
    );
    const isSignatureValid = await verify(
      authorizationASN1.signature.valueBlock.valueHex,
      gatewayPublicKey,
      expectedSignaturePlaintext,
    );
    if (!isSignatureValid) {
      throw new InvalidMessageError('Authorization signature is invalid');
    }

    const gatewayData = authorizationASN1.gatewayData.valueBlock.valueHex;
    return new PrivateNodeRegistrationAuthorization(expiryDate, gatewayData);
  }

  private static readonly SCHEMA = makeSequenceSchema('PrivateNodeRegistrationAuthorization', [
    'expiryDate',
    'gatewayData',
    'signature',
  ]);

  private static makeSignaturePlaintext(
    expiryDateASN1: DateTime,
    gatewayDataASN1: OctetString,
  ): ArrayBuffer {
    return derSerializeHeterogeneousSequence(
      new ObjectIdentifier({ value: RELAYNET_OIDS.NODE_REGISTRATION.AUTHORIZATION }),
      expiryDateASN1,
      gatewayDataASN1,
    );
  }

  constructor(public readonly expiryDate: Date, public readonly gatewayData: ArrayBuffer) {}

  public async serialize(gatewayPrivateKey: CryptoKey): Promise<ArrayBuffer> {
    const expiryDateASN1 = dateToASN1DateTimeInUTC(this.expiryDate);
    const gatewayDataASN1 = new OctetString({ valueHex: this.gatewayData });
    const signaturePlaintext = PrivateNodeRegistrationAuthorization.makeSignaturePlaintext(
      expiryDateASN1,
      gatewayDataASN1,
    );
    const signature = await sign(signaturePlaintext, gatewayPrivateKey);
    return derSerializeHeterogeneousSequence(
      expiryDateASN1,
      gatewayDataASN1,
      new OctetString({ valueHex: signature }),
    );
  }
}
