// tslint:disable:no-let

// @ts-ignore
import bufferToArray from 'buffer-to-arraybuffer';
// @ts-ignore
import * as pkijs from 'pkijs';

import {
  Certificate,
  EnvelopedData,
  generateECDHKeyPair,
  generateRSAKeyPair,
  issueEndpointCertificate,
  issueInitialDHKeyCertificate,
  OriginatorSessionKey,
  SessionEnvelopedData,
} from '..';

import { arrayBufferFrom, expectBuffersToEqual } from '../lib/_test_utils';

const TOMORROW = new Date();
TOMORROW.setDate(TOMORROW.getDate() + 1);

let nodeKeyPair: CryptoKeyPair;
let nodeCertificate: Certificate;
beforeAll(async () => {
  nodeKeyPair = await generateRSAKeyPair();
  nodeCertificate = await issueEndpointCertificate({
    issuerPrivateKey: nodeKeyPair.privateKey,
    subjectPublicKey: nodeKeyPair.publicKey,
    validityEndDate: TOMORROW,
  });
});

test('DH certificate can be issued, serialized and deserialized', async () => {
  const dhKeyPair = await generateECDHKeyPair();
  const dhCertificate = await issueInitialDHKeyCertificate({
    issuerCertificate: nodeCertificate,
    issuerPrivateKey: nodeKeyPair.privateKey,
    subjectPublicKey: dhKeyPair.publicKey,
    validityEndDate: TOMORROW,
  });

  expect(dhCertificate.getCommonName()).toEqual(nodeCertificate.getCommonName());

  const dhCertificateSerialized = dhCertificate.serialize();
  const dhCertificateDeserialized = Certificate.deserialize(dhCertificateSerialized);
  expect(dhCertificateDeserialized.getCommonName()).toEqual(dhCertificate.getCommonName());
});

test('Encryption and decryption with subsequent DH keys', async () => {
  const bobKeyPair1 = await generateECDHKeyPair();
  const bobDhCertificate = await issueInitialDHKeyCertificate({
    issuerCertificate: nodeCertificate,
    issuerPrivateKey: nodeKeyPair.privateKey,
    subjectPublicKey: bobKeyPair1.publicKey,
    validityEndDate: TOMORROW,
  });

  // Run 1: Alice initiates contact with Bob. Bob decrypts message.
  const plaintext1 = arrayBufferFrom('Hi. My name is Alice.');
  const encryptionResult1 = await SessionEnvelopedData.encrypt(plaintext1, bobDhCertificate);
  const decryptedPlaintext1 = await encryptionResult1.envelopedData.decrypt(bobKeyPair1.privateKey);
  expectBuffersToEqual(decryptedPlaintext1, plaintext1);
  checkRecipientInfo(encryptionResult1.envelopedData, bobDhCertificate);

  // Run 2: Bob replies to Alice. They have one DH key pair each.
  const plaintext2 = arrayBufferFrom('Hi, Alice. My name is Bob.');
  const alicePublicKey1 = await encryptionResult1.envelopedData.getOriginatorKey();
  const encryptionResult2 = await SessionEnvelopedData.encrypt(plaintext2, alicePublicKey1);
  const decryptedPlaintext2 = await encryptionResult2.envelopedData.decrypt(
    encryptionResult1.dhPrivateKey as CryptoKey,
  );
  expectBuffersToEqual(decryptedPlaintext2, plaintext2);
  checkRecipientInfo(encryptionResult2.envelopedData, alicePublicKey1);

  // Run 3: Alice replies to Bob. Alice has two DH key pairs and Bob just one.
  const plaintext3 = arrayBufferFrom('Nice to meet you, Bob.');
  const bobPublicKey2 = await encryptionResult2.envelopedData.getOriginatorKey();
  const encryptionResult3 = await SessionEnvelopedData.encrypt(plaintext3, bobPublicKey2);
  const decryptedPlaintext3 = await encryptionResult3.envelopedData.decrypt(
    encryptionResult2.dhPrivateKey as CryptoKey,
  );
  expectBuffersToEqual(decryptedPlaintext3, plaintext3);
  checkRecipientInfo(encryptionResult3.envelopedData, bobPublicKey2);
});

test('SessionEnvelopedData.getRecipientKeyId() can be retrieved after serialization', async () => {
  // This essentially makes sure we're not reading `recipientCertificate` on the recipientInfo
  // as PKI.js attaches it to the EnvelopedData value temporarily but isn't output to the
  // ASN.1 representation because it isn't part of the CMS serialization.
  const dhKeyPair = await generateECDHKeyPair();
  const dhCertificate = await issueInitialDHKeyCertificate({
    issuerCertificate: nodeCertificate,
    issuerPrivateKey: nodeKeyPair.privateKey,
    subjectPublicKey: dhKeyPair.publicKey,
    validityEndDate: TOMORROW,
  });

  const { envelopedData } = await SessionEnvelopedData.encrypt(arrayBufferFrom('f'), dhCertificate);

  const envelopedDataDeserialized = EnvelopedData.deserialize(
    envelopedData.serialize(),
  ) as SessionEnvelopedData;
  expect(envelopedDataDeserialized.getRecipientKeyId()).toEqual(dhCertificate.getSerialNumber());
});

test('EnvelopedData should be decrypted after serialization', async () => {
  // Make sure data can be decrypted after the EnvelopedData and/or the certificate have
  // been serialized. This is a regression test for
  // https://github.com/PeculiarVentures/PKI.js/pull/258
  const dhKeyPair = await generateECDHKeyPair();
  const dhCertificate = await issueInitialDHKeyCertificate({
    issuerCertificate: nodeCertificate,
    issuerPrivateKey: nodeKeyPair.privateKey,
    subjectPublicKey: dhKeyPair.publicKey,
    validityEndDate: TOMORROW,
  });

  const plaintext = arrayBufferFrom('plaintext');
  const { envelopedData } = await SessionEnvelopedData.encrypt(plaintext, dhCertificate);

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
  expectedRecipientCertificate: Certificate | OriginatorSessionKey,
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
  const expectedKeyId =
    expectedRecipientCertificate instanceof Certificate
      ? expectedRecipientCertificate.pkijsCertificate.serialNumber.valueBlock.valueHex
      : expectedRecipientCertificate.keyId;
  expect(envelopedData.getRecipientKeyId()).toEqual(Buffer.from(expectedKeyId));
}
