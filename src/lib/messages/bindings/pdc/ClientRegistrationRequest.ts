import { ObjectIdentifier, OctetString, verifySchema } from 'asn1js';

import { derDeserializeRSAPublicKey, derSerializePublicKey } from '../../../..';
import { tryCatchAsync } from '../../../_utils';
import { makeSequenceSchema, serializeSequence } from '../../../asn1';
import { sign, verify } from '../../../crypto_wrappers/rsaSigning';
import { CRA_COUNTERSIGNATURE } from '../../../oids';
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

    const craSerializedASN1 = request.craSerialized;
    const craCountersignature = request.craCountersignature.valueBlock.valueHex;
    const craCountersignaturePlaintext = ClientRegistrationRequest.makeCRACountersignaturePlaintext(
      craSerializedASN1,
    );
    if (!(await verify(craCountersignature, clientPublicKey, craCountersignaturePlaintext))) {
      throw new InvalidMessageError('CRA countersignature is invalid');
    }

    return new ClientRegistrationRequest(clientPublicKey, craSerializedASN1.valueBlock.valueHex);
  }

  public static makeCRACountersignaturePlaintext(craSerializedASN1: OctetString): ArrayBuffer {
    return serializeSequence(
      new ObjectIdentifier({ value: CRA_COUNTERSIGNATURE }),
      craSerializedASN1,
    );
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

    const craSerializedASN1 = new OctetString({ valueHex: this.craSerialized });
    const craCountersignaturePlaintext = ClientRegistrationRequest.makeCRACountersignaturePlaintext(
      craSerializedASN1,
    );
    const craSignature = await sign(craCountersignaturePlaintext, clientPrivateKey);

    return serializeSequence(
      new OctetString({ valueHex: clientPublicKeySerialized }),
      craSerializedASN1,
      new OctetString({ valueHex: craSignature }),
    );
  }
}
