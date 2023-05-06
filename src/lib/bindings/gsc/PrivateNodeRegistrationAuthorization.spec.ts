import { ObjectIdentifier, OctetString, Primitive, Sequence, VisibleString } from 'asn1js';
import moment from 'moment';
import { generateRSAKeyPair } from '../../../index';

import { arrayBufferFrom } from '../../_test_utils';
import { dateToASN1DateTimeInUTC, makeImplicitlyTaggedSequence } from '../../asn1';
import { derDeserialize } from '../../crypto_wrappers/_utils';
import { verify } from '../../crypto_wrappers/rsaSigning';
import { InvalidMessageError } from '../../messages/InvalidMessageError';
import { RELAYNET_OIDS } from '../../oids';
import { PrivateNodeRegistrationAuthorization } from './PrivateNodeRegistrationAuthorization';

describe('PrivateNodeRegistrationAuthorization', () => {
  const expiryDate = moment().millisecond(0).add(1, 'days').toDate();
  const gatewayData = arrayBufferFrom('This is the gateway data');

  let gatewayKeyPair: CryptoKeyPair;
  beforeAll(async () => {
    gatewayKeyPair = await generateRSAKeyPair();
  });

  describe('serialize', () => {
    const authorization = new PrivateNodeRegistrationAuthorization(expiryDate, gatewayData);

    test('Serialization should be a sequence', async () => {
      const serialization = await authorization.serialize(gatewayKeyPair.privateKey);

      const sequence = derDeserialize(serialization);
      expect(sequence).toBeInstanceOf(Sequence);
    });

    test('Expiry date should be honored', async () => {
      const serialization = await authorization.serialize(gatewayKeyPair.privateKey);

      const sequence = derDeserialize(serialization);

      const expiryDateASN1 = (sequence as Sequence).valueBlock.value[0] as Primitive;
      expect(expiryDateASN1.valueBlock.valueHex).toEqual(
        dateToASN1DateTimeInUTC(expiryDate).valueBlock.valueHex,
      );
    });

    test('Gateway data should be honored', async () => {
      const serialization = await authorization.serialize(gatewayKeyPair.privateKey);

      const sequence = derDeserialize(serialization);

      const gatewayDataASN1 = (sequence as Sequence).valueBlock.value[1] as Primitive;
      expect(gatewayDataASN1.valueBlock.valueHex).toEqual(gatewayData);
    });

    test('Signature should be valid', async () => {
      const serialization = await authorization.serialize(gatewayKeyPair.privateKey);

      const sequence = derDeserialize(serialization);
      const signatureASN1 = (sequence as Sequence).valueBlock.value[2] as Primitive;
      const signature = signatureASN1.valueBlock.valueHex;
      const expectedPlaintext = makeImplicitlyTaggedSequence(
        new ObjectIdentifier({ value: RELAYNET_OIDS.NODE_REGISTRATION.AUTHORIZATION }),
        dateToASN1DateTimeInUTC(expiryDate),
        new OctetString({ valueHex: gatewayData }),
      ).toBER();
      await expect(
        verify(signature, gatewayKeyPair.publicKey, expectedPlaintext),
      ).resolves.toBeTrue();
    });
  });

  describe('deserialize', () => {
    test('Malformed values should be refused', async () => {
      await expect(
        PrivateNodeRegistrationAuthorization.deserialize(
          arrayBufferFrom('foo'),
          gatewayKeyPair.publicKey,
        ),
      ).rejects.toEqual(
        new InvalidMessageError(
          'Serialization is not a valid PrivateNodeRegistrationAuthorization',
        ),
      );
    });

    test('Sequence should have at least 3 items', async () => {
      const serialization = makeImplicitlyTaggedSequence(
        new VisibleString({ value: 'foo' }),
        new VisibleString({ value: 'bar' }),
      ).toBER();

      await expect(
        PrivateNodeRegistrationAuthorization.deserialize(serialization, gatewayKeyPair.publicKey),
      ).rejects.toEqual(
        new InvalidMessageError(
          'Serialization is not a valid PrivateNodeRegistrationAuthorization',
        ),
      );
    });

    test('Expired authorizations should be refused', async () => {
      const oneSecondAgo = new Date();
      oneSecondAgo.setSeconds(-1);
      const authorization = new PrivateNodeRegistrationAuthorization(oneSecondAgo, gatewayData);
      const serialization = await authorization.serialize(gatewayKeyPair.privateKey);

      await expect(
        PrivateNodeRegistrationAuthorization.deserialize(serialization, gatewayKeyPair.publicKey),
      ).rejects.toEqual(new InvalidMessageError('Authorization already expired'));
    });

    test('Invalid signatures should be refused', async () => {
      const tomorrow = moment().add(1, 'days').toDate();
      const serialization = makeImplicitlyTaggedSequence(
        dateToASN1DateTimeInUTC(tomorrow),
        new VisibleString({ value: 'gateway data' }),
        new VisibleString({ value: 'invalid signature' }),
      ).toBER();

      await expect(
        PrivateNodeRegistrationAuthorization.deserialize(serialization, gatewayKeyPair.publicKey),
      ).rejects.toEqual(new InvalidMessageError('Authorization signature is invalid'));
    });

    test('Valid values should be accepted', async () => {
      const authorization = new PrivateNodeRegistrationAuthorization(expiryDate, gatewayData);
      const serialization = await authorization.serialize(gatewayKeyPair.privateKey);

      const authorizationDeserialized = await PrivateNodeRegistrationAuthorization.deserialize(
        serialization,
        gatewayKeyPair.publicKey,
      );

      expect(authorizationDeserialized.expiryDate).toEqual(expiryDate);
      expect(authorizationDeserialized.gatewayData).toEqual(gatewayData);
    });
  });
});
