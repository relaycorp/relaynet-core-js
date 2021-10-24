// @ts-ignore
import bufferToArray from 'buffer-to-arraybuffer';
// @ts-ignore
import * as pkijs from 'pkijs';

import { EnvelopedData, generateECDHKeyPair, SessionEnvelopedData } from '..';

import { arrayBufferFrom, expectBuffersToEqual } from '../lib/_test_utils';

test('Encryption and decryption with subsequent DH keys', async () => {
  const bobKeyPair1 = await generateECDHKeyPair();
  const bobKeyPair1Id = Buffer.from('bob key pair 1');

  // Run 1: Alice initiates contact with Bob. Bob decrypts message.
  const plaintext1 = arrayBufferFrom('Hi. My name is Alice.');
  const encryptionResult1 = await SessionEnvelopedData.encrypt(plaintext1, {
    keyId: bobKeyPair1Id,
    publicKey: bobKeyPair1.publicKey,
  });
  const decryptedPlaintext1 = await encryptionResult1.envelopedData.decrypt(bobKeyPair1.privateKey);
  expectBuffersToEqual(decryptedPlaintext1, plaintext1);
  checkRecipientInfo(encryptionResult1.envelopedData, bobKeyPair1Id);

  // Run 2: Bob replies to Alice. They have one DH key pair each.
  const plaintext2 = arrayBufferFrom('Hi, Alice. My name is Bob.');
  const alicePublicKey1 = await encryptionResult1.envelopedData.getOriginatorKey();
  const encryptionResult2 = await SessionEnvelopedData.encrypt(plaintext2, alicePublicKey1);
  const decryptedPlaintext2 = await encryptionResult2.envelopedData.decrypt(
    encryptionResult1.dhPrivateKey as CryptoKey,
  );
  expectBuffersToEqual(decryptedPlaintext2, plaintext2);
  checkRecipientInfo(encryptionResult2.envelopedData, alicePublicKey1.keyId);

  // Run 3: Alice replies to Bob. Alice has two DH key pairs and Bob just one.
  const plaintext3 = arrayBufferFrom('Nice to meet you, Bob.');
  const bobPublicKey2 = await encryptionResult2.envelopedData.getOriginatorKey();
  const encryptionResult3 = await SessionEnvelopedData.encrypt(plaintext3, bobPublicKey2);
  const decryptedPlaintext3 = await encryptionResult3.envelopedData.decrypt(
    encryptionResult2.dhPrivateKey as CryptoKey,
  );
  expectBuffersToEqual(decryptedPlaintext3, plaintext3);
  checkRecipientInfo(encryptionResult3.envelopedData, bobPublicKey2.keyId);
});

test('EnvelopedData should be decrypted after serialization', async () => {
  // Make sure data can be decrypted after the EnvelopedData and/or the certificate have
  // been serialized. This is a regression test for
  // https://github.com/PeculiarVentures/PKI.js/pull/258
  const dhKeyPair = await generateECDHKeyPair();
  const keyId = Buffer.from('key id');

  const plaintext = arrayBufferFrom('plaintext');
  const { envelopedData } = await SessionEnvelopedData.encrypt(plaintext, {
    keyId,
    publicKey: dhKeyPair.publicKey,
  });

  // Check it can be decrypted before serializing it:
  expectBuffersToEqual(await envelopedData.decrypt(dhKeyPair.privateKey), plaintext);

  // Check it can be decrypted after serializing and deserializing it:
  const envelopedDataDeserialized = EnvelopedData.deserialize(
    envelopedData.serialize(),
  ) as SessionEnvelopedData;
  expectBuffersToEqual(await envelopedDataDeserialized.decrypt(dhKeyPair.privateKey), plaintext);
});

function checkRecipientInfo(
  envelopedData: SessionEnvelopedData,
  expectedRecipientSessionKeyId: Buffer,
): void {
  expect(envelopedData.pkijsEnvelopedData.recipientInfos).toHaveLength(1);
  const recipientInfo = envelopedData.pkijsEnvelopedData.recipientInfos[0];

  // RecipientInfo MUST use the KeyAgreeRecipientInfo choice
  expect(recipientInfo).toHaveProperty('variant', 2);

  // KeyAgreeRecipientInfo MUST use the OriginatorPublicKey choice
  expect(recipientInfo).toHaveProperty('value.originator.variant', 3);

  // Validate keyEncryptionAlgorithm
  expect(recipientInfo.value.keyEncryptionAlgorithm).toHaveProperty(
    'algorithmId',
    '1.3.132.1.11.3', // dhSinglePass-stdDH-sha512kdf-scheme
  );
  const keyEncryptionAlgorithmParams = new pkijs.AlgorithmIdentifier({
    schema: recipientInfo.value.keyEncryptionAlgorithm.algorithmParams,
  });
  expect(keyEncryptionAlgorithmParams).toHaveProperty(
    'algorithmId',
    '2.16.840.1.101.3.4.1.45', // id-aes256-wrap
  );

  // Validate recipientEncryptedKeys
  expect(recipientInfo.value.recipientEncryptedKeys.encryptedKeys).toHaveLength(1);
  const keyAgreeRecipientIdentifier =
    recipientInfo.value.recipientEncryptedKeys.encryptedKeys[0].rid;
  expect(keyAgreeRecipientIdentifier.variant).toEqual(1);
  const expectedKeyId = bufferToArray(expectedRecipientSessionKeyId);
  expect(keyAgreeRecipientIdentifier.value.serialNumber.valueBlock.valueHex).toEqual(expectedKeyId);
}
