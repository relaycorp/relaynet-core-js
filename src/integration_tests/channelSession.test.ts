// @ts-ignore
import bufferToArray from 'buffer-to-arraybuffer';
// @ts-ignore
import * as pkijs from 'pkijs';

import { expectBuffersToEqual } from '../lib/_test_utils';
import { getPkijsCrypto } from '../lib/crypto_wrappers/_utils';
import { SessionEnvelopedData } from '../lib/crypto_wrappers/cms/envelopedData';
import { generateECDHKeyPair, generateRSAKeyPair } from '../lib/crypto_wrappers/keyGenerators';
import Certificate from '../lib/crypto_wrappers/x509/Certificate';
import { issueInitialDHKeyCertificate, issueNodeCertificate } from '../lib/nodes';

const cryptoEngine = getPkijsCrypto();

const TOMORROW = new Date();
TOMORROW.setDate(TOMORROW.getDate() + 1);

// tslint:disable-next-line:no-let
let nodeKeyPair: CryptoKeyPair;
// tslint:disable-next-line:no-let
let nodeCertificate: Certificate;
beforeAll(async () => {
  nodeKeyPair = await generateRSAKeyPair();
  nodeCertificate = await issueNodeCertificate({
    isCA: true,
    issuerPrivateKey: nodeKeyPair.privateKey,
    serialNumber: 1,
    subjectPublicKey: nodeKeyPair.publicKey,
    validityEndDate: TOMORROW,
  });
});

test('DH certificate can be issued, serialized and deserialized', async () => {
  const dhKeyPair = await generateECDHKeyPair();
  const dhCertificate = await issueInitialDHKeyCertificate({
    dhPublicKey: dhKeyPair.publicKey,
    nodeCertificate,
    nodePrivateKey: nodeKeyPair.privateKey,
    serialNumber: 2,
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
    dhPublicKey: bobKeyPair1.publicKey,
    nodeCertificate,
    nodePrivateKey: nodeKeyPair.privateKey,
    serialNumber: 2,
    validityEndDate: TOMORROW,
  });

  // Run 1: Alice initiates contact with Bob. Bob decrypts message.
  const plaintext1 = bufferToArray(Buffer.from('Hi. My name is Alice.'));
  const encryptionResult1 = await SessionEnvelopedData.encrypt(plaintext1, bobDhCertificate);
  const decryptionResult1 = await encryptionResult1.envelopedData.decrypt(
    bobKeyPair1.privateKey,
    bobDhCertificate,
  );
  expectBuffersToEqual(decryptionResult1.plaintext, plaintext1);
  checkRecipientInfo(
    encryptionResult1.envelopedData,
    decryptionResult1.dhPublicKeyDer as ArrayBuffer,
    bobDhCertificate,
  );

  // Run 2: Bob replies to Alice. They have one DH key pair each.
  const plaintext2 = bufferToArray(Buffer.from('Hi, Alice. My name is Bob.'));
  const alicePublicKey1 = await deserializeDhPublicKey(
    decryptionResult1.dhPublicKeyDer as ArrayBuffer,
  );
  const aliceDhCert1 = await issueInitialDHKeyCertificate({
    dhPublicKey: alicePublicKey1,
    nodeCertificate,
    nodePrivateKey: nodeKeyPair.privateKey,
    serialNumber: encryptionResult1.dhKeyId as number,
    validityEndDate: TOMORROW,
  });
  const encryptionResult2 = await SessionEnvelopedData.encrypt(plaintext2, aliceDhCert1);
  const decryptionResult2 = await encryptionResult2.envelopedData.decrypt(
    encryptionResult1.dhPrivateKey as CryptoKey,
    aliceDhCert1,
  );
  expectBuffersToEqual(decryptionResult2.plaintext, plaintext2);
  checkRecipientInfo(
    encryptionResult2.envelopedData,
    decryptionResult2.dhPublicKeyDer as ArrayBuffer,
    aliceDhCert1,
  );

  // Run 3: Alice replies to Bob. Alice has two DH key pairs and Bob just one.
  const plaintext3 = bufferToArray(Buffer.from('Nice to meet you, Bob.'));
  const bobPublicKey2 = await deserializeDhPublicKey(
    decryptionResult2.dhPublicKeyDer as ArrayBuffer,
  );
  const bobDhCert2 = await issueInitialDHKeyCertificate({
    dhPublicKey: bobPublicKey2,
    nodeCertificate,
    nodePrivateKey: nodeKeyPair.privateKey,
    serialNumber: encryptionResult2.dhKeyId as number,
    validityEndDate: TOMORROW,
  });
  const encryptionResult3 = await SessionEnvelopedData.encrypt(plaintext3, bobDhCert2);
  const decryptionResult3 = await encryptionResult3.envelopedData.decrypt(
    encryptionResult2.dhPrivateKey as CryptoKey,
    bobDhCert2,
  );
  expectBuffersToEqual(decryptionResult3.plaintext, plaintext3);
  checkRecipientInfo(
    encryptionResult3.envelopedData,
    decryptionResult3.dhPublicKeyDer as ArrayBuffer,
    bobDhCert2,
  );
});

async function deserializeDhPublicKey(publicKeyDer: ArrayBuffer): Promise<CryptoKey> {
  return cryptoEngine.importKey(
    'spki',
    publicKeyDer,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    [],
  );
}

function checkRecipientInfo(
  envelopedData: SessionEnvelopedData,
  expectedPublicKeyDer: ArrayBuffer,
  expectedRecipientCertificate: Certificate,
): void {
  expect(envelopedData.pkijsEnvelopedData.recipientInfos).toHaveLength(1);
  const recipientInfo = envelopedData.pkijsEnvelopedData.recipientInfos[0];

  // RecipientInfo MUST use the KeyAgreeRecipientInfo choice
  expect(recipientInfo).toHaveProperty('variant', 2);

  // KeyAgreeRecipientInfo MUST use the OriginatorPublicKey choice
  expect(recipientInfo).toHaveProperty('value.originator.variant', 3);
  const actualPublicKeyDer = recipientInfo.value.originator.value.toSchema().toBER(false);
  expectBuffersToEqual(actualPublicKeyDer, expectedPublicKeyDer);

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
  expectBuffersToEqual(
    keyAgreeRecipientIdentifier.value.issuer.toSchema().toBER(false),
    expectedRecipientCertificate.pkijsCertificate.subject.toSchema().toBER(false),
  );
  expect(keyAgreeRecipientIdentifier.value.serialNumber.valueBlock.toString()).toEqual(
    expectedRecipientCertificate.pkijsCertificate.serialNumber.valueBlock.toString(),
  );
}
