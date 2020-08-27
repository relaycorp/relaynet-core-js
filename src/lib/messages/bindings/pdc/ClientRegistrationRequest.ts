import { OctetString, verifySchema } from 'asn1js';

import { derDeserializeRSAPublicKey, derSerializePublicKey } from '../../../..';
import { tryCatchAsync } from '../../../_utils';
import { makeSequenceSchema, serializeSequence } from '../../../asn1';
import { sign, verify } from '../../../crypto_wrappers/rsaSigning';
import InvalidMessageError from '../../InvalidMessageError';

export class ClientRegistrationRequest {
  public static async deserialize(serialization: ArrayBuffer): Promise<ClientRegistrationRequest> {
    const result = verifySchema(serialization, ClientRegistrationRequest.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Serialization is not a valid ClientRegistrationRequest');
    }

    const request = (result.result as any).ClientRegistrationRequest;

    const clientPublicKey = await tryCatchAsync(
      async () => derDeserializeRSAPublicKey(request.clientPublicKey.valueBlock.valueHex),
      (error) => new InvalidMessageError('Client public key is not valid', error),
    );

    const craSerialized = request.craSerialized.valueBlock.valueHex;

    const craCountersignature = request.craCountersignature.valueBlock.valueHex;
    if (!(await verify(craCountersignature, clientPublicKey, craSerialized))) {
      throw new InvalidMessageError('CRA countersignature is invalid');
    }

    return new ClientRegistrationRequest(clientPublicKey, craSerialized);
  }

  private static readonly SCHEMA = makeSequenceSchema('ClientRegistrationRequest', [
    'clientPublicKey',
    'craSerialized',
    'craCountersignature',
  ]);

  constructor(
    public readonly clientPublicKey: CryptoKey,
    public readonly craSerialized: ArrayBuffer,
  ) {}

  public async serialize(clientPrivateKey: CryptoKey): Promise<ArrayBuffer> {
    const clientPublicKeySerialized = await derSerializePublicKey(this.clientPublicKey);
    const craSignature = await sign(this.craSerialized, clientPrivateKey);
    return serializeSequence(
      new OctetString({ valueHex: clientPublicKeySerialized }),
      new OctetString({ valueHex: this.craSerialized }),
      new OctetString({ valueHex: craSignature }),
    );
  }
}
