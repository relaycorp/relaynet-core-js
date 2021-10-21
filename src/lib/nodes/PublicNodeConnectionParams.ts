import { OctetString, VisibleString } from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';

import { derSerializeHeterogeneousSequence } from '../asn1';
import { derSerializePublicKey } from '../crypto_wrappers/keys';

export class PublicNodeConnectionParams {
  public static deserialize(serialization: ArrayBuffer): PublicNodeConnectionParams {
    throw new Error('implement!' + serialization);
  }

  constructor(
    public readonly publicAddress: string,
    public readonly identityKey: CryptoKey,
    public readonly sessionKey: CryptoKey,
  ) {}

  public async serialize(): Promise<ArrayBuffer> {
    const identityKeySerialized = await derSerializePublicKey(this.identityKey);
    const sessionKeySerialized = await derSerializePublicKey(this.sessionKey);
    return derSerializeHeterogeneousSequence(
      new VisibleString({ value: this.publicAddress }),
      new OctetString({ valueHex: bufferToArray(identityKeySerialized) }),
      new OctetString({ valueHex: bufferToArray(sessionKeySerialized) }),
    );
  }
}
