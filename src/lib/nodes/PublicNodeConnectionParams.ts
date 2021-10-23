import { OctetString, Primitive, verifySchema, VisibleString } from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import isValidDomain from 'is-valid-domain';
import { TextDecoder } from 'util';

import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../asn1';
import {
  derDeserializeECDHPublicKey,
  derDeserializeRSAPublicKey,
  derSerializePublicKey,
} from '../crypto_wrappers/keys';
import { SessionKey } from '../SessionKey';
import { InvalidPublicNodeConnectionParams } from './InvalidPublicNodeConnectionParams';

export class PublicNodeConnectionParams {
  public static async deserialize(serialization: ArrayBuffer): Promise<PublicNodeConnectionParams> {
    const result = verifySchema(serialization, PublicNodeConnectionParams.SCHEMA);
    if (!result.verified) {
      throw new InvalidPublicNodeConnectionParams(
        'Serialization is not a valid PublicNodeConnectionParams',
      );
    }

    const paramsASN1 = (result.result as any).PublicNodeConnectionParams;

    const textDecoder = new TextDecoder();
    const publicAddress = textDecoder.decode(paramsASN1.publicAddress.valueBlock.valueHex);
    if (!isValidDomain(publicAddress)) {
      throw new InvalidPublicNodeConnectionParams(
        `Public address is syntactically invalid (${publicAddress})`,
      );
    }

    let identityKey: CryptoKey;
    try {
      identityKey = await derDeserializeRSAPublicKey(paramsASN1.identityKey.valueBlock.valueHex);
    } catch (err) {
      throw new InvalidPublicNodeConnectionParams(
        new Error(err), // The original error could be a string 🤦
        'Identity key is not a valid RSA public key',
      );
    }
    let sessionKey: CryptoKey;
    try {
      sessionKey = await derDeserializeECDHPublicKey(paramsASN1.sessionKey.valueBlock.valueHex);
    } catch (err) {
      throw new InvalidPublicNodeConnectionParams(
        new Error(err), // The original error could be a string 🤦
        'Session key is not a valid ECDH public key',
      );
    }

    return new PublicNodeConnectionParams(publicAddress, identityKey, sessionKey as any);
  }

  private static readonly SCHEMA = makeHeterogeneousSequenceSchema('PublicNodeConnectionParams', [
    new Primitive({ name: 'publicAddress' }),
    new Primitive({ name: 'identityKey' }),
    new Primitive({ name: 'sessionKey' }),
  ]);

  constructor(
    public readonly publicAddress: string,
    public readonly identityKey: CryptoKey,
    public readonly sessionKey: SessionKey,
  ) {}

  public async serialize(): Promise<ArrayBuffer> {
    const identityKeySerialized = await derSerializePublicKey(this.identityKey);

    const sessionPublicKeySerialized = await derSerializePublicKey(this.sessionKey.publicKey);
    const sessionKeySequence = makeImplicitlyTaggedSequence(
      new OctetString({ valueHex: bufferToArray(this.sessionKey.keyId) }),
      new OctetString({ valueHex: bufferToArray(sessionPublicKeySerialized) }),
    );

    return makeImplicitlyTaggedSequence(
      new VisibleString({ value: this.publicAddress }),
      new OctetString({ valueHex: bufferToArray(identityKeySerialized) }),
      sessionKeySequence,
    ).toBER();
  }
}
