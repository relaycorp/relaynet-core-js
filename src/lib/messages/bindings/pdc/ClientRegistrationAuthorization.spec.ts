import { ObjectIdentifier, OctetString, Primitive, Sequence } from 'asn1js';
import moment from 'moment';
import { generateRSAKeyPair } from '../../../..';

import { arrayBufferFrom } from '../../../_test_utils';
import { dateToASN1DateTimeInUTC, serializeSequence } from '../../../asn1';
import { derDeserialize } from '../../../crypto_wrappers/_utils';
import { verify } from '../../../crypto_wrappers/rsaSigning';
import { CRA } from '../../../oids';
import { ClientRegistrationAuthorization } from './ClientRegistrationAuthorization';

describe('ClientRegistrationAuthorization', () => {
  const expiryDate = moment().add(1, 'days').toDate();
  const serverData = arrayBufferFrom('This is the server data');

  // tslint:disable-next-line:no-let
  let serverKeyPair: CryptoKeyPair;
  beforeAll(async () => {
    serverKeyPair = await generateRSAKeyPair();
  });

  describe('serialize', () => {
    const authorization = new ClientRegistrationAuthorization(expiryDate, serverData);

    test('Serialization should be a sequence', async () => {
      const serialization = await authorization.serialize(serverKeyPair.privateKey);

      const sequence = derDeserialize(serialization);
      expect(sequence).toBeInstanceOf(Sequence);
    });

    test('Expiry date should be honored', async () => {
      const serialization = await authorization.serialize(serverKeyPair.privateKey);

      const sequence = derDeserialize(serialization);

      const expiryDateASN1 = (sequence as Sequence).valueBlock.value[0] as Primitive;
      expect(expiryDateASN1.valueBlock.valueHex).toEqual(
        dateToASN1DateTimeInUTC(expiryDate).valueBlock.valueHex,
      );
    });

    test('Server data should be honored', async () => {
      const serialization = await authorization.serialize(serverKeyPair.privateKey);

      const sequence = derDeserialize(serialization);

      const serverDataASN1 = (sequence as Sequence).valueBlock.value[1] as Primitive;
      expect(serverDataASN1.valueBlock.valueHex).toEqual(serverData);
    });

    test('Signature should be valid', async () => {
      const serialization = await authorization.serialize(serverKeyPair.privateKey);

      const sequence = derDeserialize(serialization);
      const signatureASN1 = (sequence as Sequence).valueBlock.value[2] as Primitive;
      const signature = signatureASN1.valueBlock.valueHex;
      const expectedPlaintext = serializeSequence(
        new ObjectIdentifier({ value: CRA }),
        dateToASN1DateTimeInUTC(expiryDate),
        new OctetString({ valueHex: serverData }),
      );
      await expect(
        verify(signature, serverKeyPair.publicKey, expectedPlaintext),
      ).resolves.toBeTrue();
    });
  });
});
