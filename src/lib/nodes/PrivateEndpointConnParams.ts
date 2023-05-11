import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Certificate as CertificateSchema, SubjectPublicKeyInfo } from '@peculiar/asn1-x509';

import { SessionKey } from '../SessionKey';
import { CertificationPath } from '../pki/CertificationPath';
import { PrivateEndpointConnParamsSchema } from '../schemas/PrivateEndpointConnParamsSchema';
import {
  derDeserializeECDHPublicKey,
  derDeserializeRSAPublicKey,
  derSerializePublicKey,
} from '../crypto/keys/serialisation';
import { SessionKeySchema } from '../schemas/SessionKeySchema';
import { CertificationPathSchema } from '../schemas/CertificationPathSchema';
import { Certificate } from '../crypto/x509/Certificate';
import { CertificateSetSchema } from '../schemas/CertificateSetSchema';
import { InvalidNodeConnectionParams } from './errors';

export class PrivateEndpointConnParams {
  public static async deserialize(serialization: ArrayBuffer): Promise<PrivateEndpointConnParams> {
    let schema: PrivateEndpointConnParamsSchema;
    try {
      schema = AsnParser.parse(serialization, PrivateEndpointConnParamsSchema);
    } catch {
      throw new InvalidNodeConnectionParams('Private endpoint connection params is malformed');
    }

    const identityKey = await derDeserializeRSAPublicKey(
      AsnSerializer.serialize(schema.identityKey),
    );
    const sessionPublicKey = await derDeserializeECDHPublicKey(
      AsnSerializer.serialize(schema.sessionKey.publicKey),
    );
    const leafCertificate = convertAsnToCertificate(schema.deliveryAuth.leaf);
    const cas = schema.deliveryAuth.certificateAuthorities.map(convertAsnToCertificate);
    return new PrivateEndpointConnParams(
      identityKey,
      schema.internetGatewayAddress,
      { keyId: Buffer.from(schema.sessionKey.keyId), publicKey: sessionPublicKey },
      new CertificationPath(leafCertificate, cas),
    );
  }

  public constructor(
    public readonly identityKey: CryptoKey,
    public readonly internetGatewayAddress: string,
    public readonly sessionKey: SessionKey,
    public readonly deliveryAuth: CertificationPath,
  ) {}

  public async serialize(): Promise<ArrayBuffer> {
    const schema = new PrivateEndpointConnParamsSchema();

    schema.identityKey = AsnParser.parse(
      await derSerializePublicKey(this.identityKey),
      SubjectPublicKeyInfo,
    );

    schema.internetGatewayAddress = this.internetGatewayAddress;

    schema.sessionKey = new SessionKeySchema();
    schema.sessionKey.keyId = this.sessionKey.keyId;
    schema.sessionKey.publicKey = AsnParser.parse(
      await derSerializePublicKey(this.sessionKey.publicKey),
      SubjectPublicKeyInfo,
    );

    schema.deliveryAuth = new CertificationPathSchema();
    schema.deliveryAuth.leaf = convertCertificateToAsn(this.deliveryAuth.leafCertificate);
    schema.deliveryAuth.certificateAuthorities = new CertificateSetSchema(
      this.deliveryAuth.certificateAuthorities.map(convertCertificateToAsn),
    );

    return AsnSerializer.serialize(schema);
  }
}

function convertCertificateToAsn(certificate: Certificate): CertificateSchema {
  return AsnParser.parse(certificate.serialize(), CertificateSchema);
}

function convertAsnToCertificate(asn: CertificateSchema): Certificate {
  return Certificate.deserialize(AsnSerializer.serialize(asn));
}
