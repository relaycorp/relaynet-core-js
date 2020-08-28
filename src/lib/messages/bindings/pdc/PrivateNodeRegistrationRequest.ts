import { ObjectIdentifier, OctetString, verifySchema } from 'asn1js';

import { derDeserializeRSAPublicKey, derSerializePublicKey } from '../../../..';
import { tryCatchAsync } from '../../../_utils';
import { makeSequenceSchema, serializeSequence } from '../../../asn1';
import { sign, verify } from '../../../crypto_wrappers/rsaSigning';
import { PNRA_COUNTERSIGNATURE } from '../../../oids';
import InvalidMessageError from '../../InvalidMessageError';

export class PrivateNodeRegistrationRequest {
  public static async deserialize(
    serialization: ArrayBuffer,
  ): Promise<PrivateNodeRegistrationRequest> {
    const result = verifySchema(serialization, PrivateNodeRegistrationRequest.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Serialization is not a valid PrivateNodeRegistrationRequest');
    }

    const request = (result.result as any).PrivateNodeRegistrationRequest;

    const privateNodePublicKey = await tryCatchAsync(
      async () => derDeserializeRSAPublicKey(request.privateNodePublicKey.valueBlock.valueHex),
      (error) => new InvalidMessageError('Private node public key is not valid', error),
    );

    const authorizationSerializedASN1 = request.pnraSerialized;
    const countersignature = request.countersignature.valueBlock.valueHex;
    const countersignaturePlaintext = PrivateNodeRegistrationRequest.makePNRACountersignaturePlaintext(
      authorizationSerializedASN1,
    );
    if (!(await verify(countersignature, privateNodePublicKey, countersignaturePlaintext))) {
      throw new InvalidMessageError('Authorization countersignature is invalid');
    }

    return new PrivateNodeRegistrationRequest(
      privateNodePublicKey,
      authorizationSerializedASN1.valueBlock.valueHex,
    );
  }

  public static makePNRACountersignaturePlaintext(pnraSerializedASN1: OctetString): ArrayBuffer {
    return serializeSequence(
      new ObjectIdentifier({ value: PNRA_COUNTERSIGNATURE }),
      pnraSerializedASN1,
    );
  }

  private static readonly SCHEMA = makeSequenceSchema('PrivateNodeRegistrationRequest', [
    'privateNodePublicKey',
    'pnraSerialized',
    'countersignature',
  ]);

  constructor(
    public readonly privateNodePublicKey: CryptoKey,
    public readonly pnraSerialized: ArrayBuffer,
  ) {
  }

  public async serialize(privateNodePrivateKey: CryptoKey): Promise<ArrayBuffer> {
    const privateNodePublicKeySerialized = await derSerializePublicKey(this.privateNodePublicKey);

    const authorizationSerializedASN1 = new OctetString({ valueHex: this.pnraSerialized });
    const countersignaturePlaintext = PrivateNodeRegistrationRequest.makePNRACountersignaturePlaintext(
      authorizationSerializedASN1,
    );
    const signature = await sign(countersignaturePlaintext, privateNodePrivateKey);

    return serializeSequence(
      new OctetString({ valueHex: privateNodePublicKeySerialized }),
      authorizationSerializedASN1,
      new OctetString({ valueHex: signature }),
    );
  }
}
