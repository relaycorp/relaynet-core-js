import { Constructed, OctetString, Primitive, verifySchema, VisibleString } from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import isValidDomain from 'is-valid-domain';
import { TextDecoder } from 'util';

import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../../asn1';
import { derDeserializeECDHPublicKey, derSerializePublicKey } from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import InvalidMessageError from '../../messages/InvalidMessageError';
import { SessionKey } from '../../SessionKey';

export class PrivateNodeRegistration {
  public static async deserialize(serialization: ArrayBuffer): Promise<PrivateNodeRegistration> {
    const result = verifySchema(serialization, PrivateNodeRegistration.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Serialization is not a valid PrivateNodeRegistration');
    }
    const registrationASN1 = (result.result as any).PrivateNodeRegistration;

    let privateNodeCertificate: Certificate;
    try {
      privateNodeCertificate = Certificate.deserialize(
        registrationASN1.privateNodeCertificate.valueBlock.valueHex,
      );
    } catch (err) {
      throw new InvalidMessageError(err as Error, 'Private node certificate is invalid');
    }

    let gatewayCertificate: Certificate;
    try {
      gatewayCertificate = Certificate.deserialize(
        registrationASN1.gatewayCertificate.valueBlock.valueHex,
      );
    } catch (err) {
      throw new InvalidMessageError(err as Error, 'Gateway certificate is invalid');
    }

    const textDecoder = new TextDecoder();
    const publicGatewayInternetAddress = textDecoder.decode(
      registrationASN1.publicGatewayInternetAddress.valueBlock.valueHex,
    );
    if (!isValidDomain(publicGatewayInternetAddress)) {
      throw new InvalidMessageError(
        `Malformed public gateway address (${publicGatewayInternetAddress})`,
      );
    }

    const sessionKey = await deserializeSessionKey(registrationASN1.sessionKey);

    return new PrivateNodeRegistration(
      privateNodeCertificate,
      gatewayCertificate,
      publicGatewayInternetAddress,
      sessionKey,
    );
  }

  private static readonly SCHEMA = makeHeterogeneousSequenceSchema('PrivateNodeRegistration', [
    new Primitive({ name: 'privateNodeCertificate' }),
    new Primitive({ name: 'gatewayCertificate' }),
    new Primitive({ name: 'publicGatewayInternetAddress' }),
    new Constructed({
      name: 'sessionKey',
      optional: true,
      value: [
        new Primitive({ idBlock: { tagClass: 3, tagNumber: 0 } }),
        new Primitive({ idBlock: { tagClass: 3, tagNumber: 1 } }),
      ],
    }),
  ]);

  constructor(
    public readonly privateNodeCertificate: Certificate,
    public readonly gatewayCertificate: Certificate,
    public readonly publicGatewayInternetAddress: string,
    public readonly sessionKey: SessionKey | null = null,
  ) {}

  public async serialize(): Promise<ArrayBuffer> {
    let sessionKeySequence = null;
    if (this.sessionKey) {
      const sessionPublicKeySerialized = await derSerializePublicKey(this.sessionKey.publicKey);
      sessionKeySequence = makeImplicitlyTaggedSequence(
        new OctetString({ valueHex: bufferToArray(this.sessionKey.keyId) }),
        new OctetString({ valueHex: bufferToArray(sessionPublicKeySerialized) }),
      );
    }

    return makeImplicitlyTaggedSequence(
      new OctetString({ valueHex: this.privateNodeCertificate.serialize() }),
      new OctetString({ valueHex: this.gatewayCertificate.serialize() }),
      new VisibleString({ value: this.publicGatewayInternetAddress }),
      ...(sessionKeySequence ? [sessionKeySequence] : []),
    ).toBER();
  }
}

async function deserializeSessionKey(sessionKeySequence: any): Promise<SessionKey | null> {
  if (!sessionKeySequence) {
    return null;
  }
  if (sessionKeySequence.valueBlock.value.length < 2) {
    throw new InvalidMessageError('Session key SEQUENCE should have at least 2 items');
  }
  const sessionPublicKeyASN1 = sessionKeySequence.valueBlock.value[1] as Primitive;
  const sessionKeyIdASN1 = sessionKeySequence.valueBlock.value[0] as Primitive;
  let sessionPublicKey: CryptoKey;
  try {
    sessionPublicKey = await derDeserializeECDHPublicKey(
      sessionPublicKeyASN1.valueBlock.valueHexView,
    );
  } catch (err: any) {
    throw new InvalidMessageError(
      new Error(err), // The original error could be a string 🤦
      'Session key is not a valid ECDH public key',
    );
  }
  return {
    keyId: Buffer.from(sessionKeyIdASN1.valueBlock.valueHexView),
    publicKey: sessionPublicKey,
  };
}
