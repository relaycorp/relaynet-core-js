/* tslint:disable:no-let */
import bufferToArray from 'buffer-to-arraybuffer';

import { generateStubCert, getMockContext } from '../_test_utils';
import { generateRSAKeyPair } from '../crypto_wrappers/keys';
import * as serialization from '../ramf/serialization';
import Message from './Message';

interface MessageClass<M extends Message<any>> {
  readonly deserialize: (serialization: ArrayBuffer) => Promise<M>;
  // tslint:disable-next-line:no-mixed-interface
  new (...args: readonly any[]): M;
}

export function describeMessage<M extends Message<any>>(
  messageClass: MessageClass<M>,
  messageType: number,
  messageVersion: number,
): void {
  afterAll(() => {
    jest.restoreAllMocks();
  });

  let message: M;
  let senderPrivateKey: CryptoKey;

  beforeAll(async () => {
    const senderKeyPair = await generateRSAKeyPair();
    const senderCertificate = await generateStubCert({
      issuerPrivateKey: senderKeyPair.privateKey,
    });
    senderPrivateKey = senderKeyPair.privateKey;
    message = new messageClass('address', senderCertificate, Buffer.from('hi'));
  });

  describe('serialize', () => {
    const expectedSerialization = bufferToArray(Buffer.from('serialized'));
    const serializeSpy = jest.spyOn(serialization, 'serialize');
    beforeAll(() => {
      serializeSpy.mockResolvedValueOnce(expectedSerialization);
    });
    afterEach(() => {
      serializeSpy.mockReset();
    });

    test('Result should be RAMF serialization', async () => {
      const messageSerialized = await message.serialize(senderPrivateKey);

      expect(serializeSpy).toBeCalledTimes(1);
      expect(messageSerialized).toBe(expectedSerialization);
    });

    test(`Concrete message type should be ${messageType}`, async () => {
      await message.serialize(senderPrivateKey);

      const serializeCallArs = getMockContext(serialization.serialize).calls[0];
      expect(serializeCallArs[1]).toEqual(messageType);
    });

    test(`Concrete message version should be ${messageVersion}`, async () => {
      await message.serialize(senderPrivateKey);

      const serializeCallArs = getMockContext(serialization.serialize).calls[0];
      expect(serializeCallArs[2]).toEqual(messageVersion);
    });

    test('Message should be signed with private key specified', async () => {
      await message.serialize(senderPrivateKey);

      const serializeCallArs = getMockContext(serialization.serialize).calls[0];
      expect(serializeCallArs[3]).toEqual(senderPrivateKey);
    });

    test('Signature options should be honored', async () => {
      const signatureOptions = { hashingAlgorithmName: 'SHA-384' };
      await message.serialize(senderPrivateKey, signatureOptions);

      const serializeCallArs = getMockContext(serialization.serialize).calls[0];
      expect(serializeCallArs[4]).toEqual(signatureOptions);
    });
  });

  describe('deserialize', () => {
    const stubMessageSerialized = bufferToArray(Buffer.from('I am a message. I swear.'));
    const deserializeSpy = jest.spyOn(serialization, 'deserialize');
    beforeAll(() => {
      deserializeSpy.mockResolvedValueOnce(message);
    });
    afterEach(() => {
      deserializeSpy.mockReset();
    });

    test('Result should be the expected message', async () => {
      const messageDeserialized = await messageClass.deserialize(stubMessageSerialized);

      expect(messageDeserialized).toBe(message);
      expect(deserializeSpy).toBeCalledTimes(1);
      const deserializeCallArgs = getMockContext(deserializeSpy).calls[0];
      expect(deserializeCallArgs[0]).toBe(stubMessageSerialized);
    });

    test(`Concrete message type should be ${messageType}`, async () => {
      await messageClass.deserialize(stubMessageSerialized);

      const deserializeCallArgs = getMockContext(deserializeSpy).calls[0];
      expect(deserializeCallArgs[1]).toEqual(messageType);
    });

    test(`Concrete message version should be ${messageVersion}`, async () => {
      await messageClass.deserialize(stubMessageSerialized);

      const deserializeCallArgs = getMockContext(deserializeSpy).calls[0];
      expect(deserializeCallArgs[2]).toEqual(messageVersion);
    });

    test(`Message class should be ${messageClass.name}`, async () => {
      await messageClass.deserialize(stubMessageSerialized);

      const deserializeCallArgs = getMockContext(deserializeSpy).calls[0];
      expect(deserializeCallArgs[3]).toBe(messageClass);
    });
  });
}
