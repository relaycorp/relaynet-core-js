import { Constructed, OctetString, Primitive, Sequence, verifySchema, VisibleString } from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import isValidDomain from 'is-valid-domain';
import { TextDecoder } from 'util';

import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../asn1';
import { SessionKey } from '../SessionKey';
import { InvalidNodeConnectionParams } from './errors';
import {
  derDeserializeECDHPublicKey,
  derDeserializeRSAPublicKey,
  derSerializePublicKey,
} from '../crypto/keys/serialisation';

export class NodeConnectionParams {
  public static async deserialize(serialization: ArrayBuffer): Promise<NodeConnectionParams> {
    const result = verifySchema(serialization, NodeConnectionParams.SCHEMA);
    if (!result.verified) {
      throw new InvalidNodeConnectionParams('Serialization is not a valid NodeConnectionParams');
    }

    const paramsASN1 = (result.result as any).NodeConnectionParams;

    const textDecoder = new TextDecoder();
    const internetAddress = textDecoder.decode(paramsASN1.internetAddress.valueBlock.valueHex);
    if (!isValidDomain(internetAddress)) {
      throw new InvalidNodeConnectionParams(
        `Internet address is syntactically invalid (${internetAddress})`,
      );
    }

    let identityKey: CryptoKey;
    try {
      identityKey = await derDeserializeRSAPublicKey(paramsASN1.identityKey.valueBlock.valueHex);
    } catch (err: any) {
      throw new InvalidNodeConnectionParams(
        new Error(err), // The original error could be a string 🤦
        'Identity key is not a valid RSA public key',
      );
    }

    const sessionKeySequence = paramsASN1.sessionKey as Sequence;
    if (sessionKeySequence.valueBlock.value.length < 2) {
      throw new InvalidNodeConnectionParams('Session key should have at least two items');
    }
    const sessionKeyId = (sessionKeySequence.valueBlock.value[0] as Primitive).valueBlock.valueHex;
    const sessionPublicKeyASN1 = sessionKeySequence.valueBlock.value[1] as Primitive;
    let sessionPublicKey: CryptoKey;
    try {
      sessionPublicKey = await derDeserializeECDHPublicKey(
        sessionPublicKeyASN1.valueBlock.valueHex,
      );
    } catch (err: any) {
      throw new InvalidNodeConnectionParams(
        new Error(err), // The original error could be a string 🤦
        'Session key is not a valid ECDH public key',
      );
    }

    return new NodeConnectionParams(internetAddress, identityKey, {
      keyId: Buffer.from(sessionKeyId),
      publicKey: sessionPublicKey,
    });
  }

  private static readonly SCHEMA = makeHeterogeneousSequenceSchema('NodeConnectionParams', [
    new Primitive({ name: 'internetAddress' }),
    new Primitive({ name: 'identityKey' }),
    new Constructed({
      name: 'sessionKey',
      value: [
        new Primitive({ idBlock: { tagClass: 3, tagNumber: 0 } }),
        new Primitive({ idBlock: { tagClass: 3, tagNumber: 1 } }),
      ],
    }),
  ]);

  constructor(
    public readonly internetAddress: string,
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
      new VisibleString({ value: this.internetAddress }),
      new OctetString({ valueHex: bufferToArray(identityKeySerialized) }),
      sessionKeySequence,
    ).toBER();
  }
}
