/* tslint:disable:no-let */
import bufferToArray from 'buffer-to-arraybuffer';

import { generateStubCert, getMockContext } from './_test_utils';
import { generateRSAKeyPair } from './crypto_wrappers/keyGenerators';
import Parcel from './Parcel';
import * as serialization from './ramf/serialization';

afterAll(() => {
  jest.restoreAllMocks();
});

describe('Parcel', () => {
  describe('serialize', () => {
    let parcel: Parcel;
    let senderPrivateKey: CryptoKey;
    beforeAll(async () => {
      const senderKeyPair = await generateRSAKeyPair();
      const senderCertificate = await generateStubCert({
        issuerPrivateKey: senderKeyPair.privateKey,
      });
      senderPrivateKey = senderKeyPair.privateKey;
      parcel = new Parcel('address', senderCertificate, bufferToArray(Buffer.from('hi')));
    });

    const expectedSerialization = bufferToArray(Buffer.from('serialized'));
    const serializeSpy = jest.spyOn(serialization, 'serialize');
    beforeAll(() => {
      serializeSpy.mockResolvedValueOnce(expectedSerialization);
    });
    afterEach(() => {
      serializeSpy.mockReset();
    });

    test('Result should be RAMF serialization', async () => {
      const messageSerialized = await parcel.serialize(senderPrivateKey);

      expect(serializeSpy).toBeCalledTimes(1);
      expect(messageSerialized).toBe(expectedSerialization);
    });

    test('Concrete message type should be 0x50', async () => {
      await parcel.serialize(senderPrivateKey);

      const serializeCallArs = getMockContext(serialization.serialize).calls[0];
      expect(serializeCallArs[1]).toEqual(0x50);
    });

    test('Concrete message version should be 0x0', async () => {
      await parcel.serialize(senderPrivateKey);

      const serializeCallArs = getMockContext(serialization.serialize).calls[0];
      expect(serializeCallArs[2]).toEqual(0);
    });

    test('Message should be signed with private key specified', async () => {
      await parcel.serialize(senderPrivateKey);

      const serializeCallArs = getMockContext(serialization.serialize).calls[0];
      expect(serializeCallArs[3]).toEqual(senderPrivateKey);
    });

    test('Signature options should be honored', async () => {
      const signatureOptions = { hashingAlgorithmName: 'SHA-384' };
      await parcel.serialize(senderPrivateKey, signatureOptions);

      const serializeCallArs = getMockContext(serialization.serialize).calls[0];
      expect(serializeCallArs[4]).toEqual(signatureOptions);
    });
  });
});
