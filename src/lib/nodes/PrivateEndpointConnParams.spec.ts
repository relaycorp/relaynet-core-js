import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { addDays, setMilliseconds } from 'date-fns';

import { generateECDHKeyPair, generateRSAKeyPair } from '../crypto/keys/generation';
import { PrivateEndpointConnParams } from './PrivateEndpointConnParams';
import { SessionKey } from '../SessionKey';
import { reSerializeCertificate } from '../_test_utils';
import { issueGatewayCertificate } from '../pki/issuance';
import { CertificationPath } from '../pki/CertificationPath';
import { PrivateEndpointConnParamsSchema } from '../schemas/PrivateEndpointConnParamsSchema';
import { derSerializePublicKey } from '../crypto/keys/serialisation';
import { InvalidNodeConnectionParams } from './errors';

const INTERNET_ADDRESS = 'example.com';

let peerIdentityKeyPair: CryptoKeyPair;
let peerSessionKey: SessionKey;
beforeAll(async () => {
  peerIdentityKeyPair = await generateRSAKeyPair();

  const sessionKeyPair = await generateECDHKeyPair();
  peerSessionKey = {
    keyId: Buffer.from('key id'),
    publicKey: sessionKeyPair.publicKey,
  };
});

let deliveryAuth: CertificationPath;
beforeAll(async () => {
  const tomorrow = setMilliseconds(addDays(new Date(), 1), 0);

  const peerCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerPrivateKey: peerIdentityKeyPair.privateKey,
      subjectPublicKey: peerIdentityKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );

  const nodeKeyPair = await generateRSAKeyPair();
  const nodeCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: peerCertificate,
      issuerPrivateKey: peerIdentityKeyPair.privateKey,
      subjectPublicKey: nodeKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );

  deliveryAuth = new CertificationPath(nodeCertificate, [peerCertificate]);
});

describe('PrivateEndpointConnParams', () => {
  describe('serialise', () => {
    test('Identity key should be serialised', async () => {
      const params = new PrivateEndpointConnParams(
        peerIdentityKeyPair.publicKey,
        INTERNET_ADDRESS,
        deliveryAuth,
        peerSessionKey,
      );

      const serialisation = await params.serialize();

      const paramsDeserialized = AsnParser.parse(serialisation, PrivateEndpointConnParamsSchema);
      const identityKeySerialized = Buffer.from(
        AsnSerializer.serialize(paramsDeserialized.identityKey),
      );
      expect(identityKeySerialized).toStrictEqual(
        await derSerializePublicKey(peerIdentityKeyPair.publicKey),
      );
    });

    test('Internet gateway address should be serialised', async () => {
      const params = new PrivateEndpointConnParams(
        peerIdentityKeyPair.publicKey,
        INTERNET_ADDRESS,
        deliveryAuth,
        peerSessionKey,
      );

      const serialisation = await params.serialize();

      const paramsDeserialized = AsnParser.parse(serialisation, PrivateEndpointConnParamsSchema);
      expect(paramsDeserialized.internetGatewayAddress).toStrictEqual(INTERNET_ADDRESS);
    });

    test('Delivery authorisation should be serialised', async () => {
      const params = new PrivateEndpointConnParams(
        peerIdentityKeyPair.publicKey,
        INTERNET_ADDRESS,
        deliveryAuth,
        peerSessionKey,
      );

      const serialisation = await params.serialize();

      const paramsDeserialized = AsnParser.parse(serialisation, PrivateEndpointConnParamsSchema);
      expect(
        Buffer.from(AsnSerializer.serialize(paramsDeserialized.deliveryAuth.leaf)),
      ).toStrictEqual(Buffer.from(deliveryAuth.leafCertificate.serialize()));
      expect(paramsDeserialized.deliveryAuth.certificateAuthorities).toHaveLength(1);
      const [ca] = paramsDeserialized.deliveryAuth.certificateAuthorities;
      expect(Buffer.from(AsnSerializer.serialize(ca))).toStrictEqual(
        Buffer.from(deliveryAuth.certificateAuthorities[0].serialize()),
      );
    });

    test('Session key should be serialised if present', async () => {
      const params = new PrivateEndpointConnParams(
        peerIdentityKeyPair.publicKey,
        INTERNET_ADDRESS,
        deliveryAuth,
        peerSessionKey,
      );

      const serialisation = await params.serialize();

      const paramsDeserialized = AsnParser.parse(serialisation, PrivateEndpointConnParamsSchema);
      expect(Buffer.from(paramsDeserialized.sessionKey!.keyId)).toStrictEqual(peerSessionKey.keyId);
      expect(
        Buffer.from(AsnSerializer.serialize(paramsDeserialized.sessionKey!.publicKey)),
      ).toStrictEqual(await derSerializePublicKey(peerSessionKey.publicKey));
    });

    test('Session key should be skipped if missing', async () => {
      const params = new PrivateEndpointConnParams(
        peerIdentityKeyPair.publicKey,
        INTERNET_ADDRESS,
        deliveryAuth,
      );

      const serialisation = await params.serialize();

      const paramsDeserialized = AsnParser.parse(serialisation, PrivateEndpointConnParamsSchema);
      expect(paramsDeserialized.sessionKey).toBeUndefined();
    });
  });

  describe('deserialize', () => {
    let paramsSerialized: ArrayBuffer;
    beforeAll(async () => {
      const params = new PrivateEndpointConnParams(
        peerIdentityKeyPair.publicKey,
        INTERNET_ADDRESS,
        deliveryAuth,
        peerSessionKey,
      );
      paramsSerialized = await params.serialize();
    });

    test('Malformed serialization should be refused', async () => {
      await expect(
        PrivateEndpointConnParams.deserialize(Buffer.from('malformed')),
      ).rejects.toThrowWithMessage(
        InvalidNodeConnectionParams,
        'Private endpoint connection params is malformed',
      );
    });

    test('Identity key should be output', async () => {
      const params = await PrivateEndpointConnParams.deserialize(paramsSerialized);

      await expect(derSerializePublicKey(params.identityKey)).resolves.toStrictEqual(
        await derSerializePublicKey(peerIdentityKeyPair.publicKey),
      );
    });

    test('Internet gateway address should be output', async () => {
      const params = await PrivateEndpointConnParams.deserialize(paramsSerialized);

      expect(params.internetGatewayAddress).toStrictEqual(INTERNET_ADDRESS);
    });

    test('Delivery authorisation should be output', async () => {
      const params = await PrivateEndpointConnParams.deserialize(paramsSerialized);

      expect(params.deliveryAuth.leafCertificate.isEqual(deliveryAuth.leafCertificate)).toBeTrue();
      expect(params.deliveryAuth.certificateAuthorities).toHaveLength(1);
      expect(
        params.deliveryAuth.certificateAuthorities[0].isEqual(
          deliveryAuth.certificateAuthorities[0],
        ),
      ).toBeTrue();
    });

    test('Session key should be output if present', async () => {
      const params = await PrivateEndpointConnParams.deserialize(paramsSerialized);

      expect(params.sessionKey!.keyId).toStrictEqual(peerSessionKey.keyId);
      await expect(derSerializePublicKey(params.sessionKey!.publicKey)).resolves.toStrictEqual(
        await derSerializePublicKey(peerSessionKey.publicKey),
      );
    });

    test('Session should be skipped if absent', async () => {
      const params = new PrivateEndpointConnParams(
        peerIdentityKeyPair.publicKey,
        INTERNET_ADDRESS,
        deliveryAuth,
      );
      const serialization = await params.serialize();

      const paramsDeserialized = await PrivateEndpointConnParams.deserialize(serialization);

      expect(paramsDeserialized.sessionKey).toBeUndefined();
    });
  });
});
