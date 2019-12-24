// @ts-ignore
import bufferToArray from 'buffer-to-arraybuffer';

import { expectBuffersToEqual } from '../lib/_test_utils';
import { getPkijsCrypto } from '../lib/crypto_wrappers/_utils';
import * as cms from '../lib/crypto_wrappers/cms';
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
  const bobDhKeyPair = await generateECDHKeyPair();
  const bobDhCertificate = await issueInitialDHKeyCertificate({
    dhPublicKey: bobDhKeyPair.publicKey,
    nodeCertificate,
    nodePrivateKey: nodeKeyPair.privateKey,
    serialNumber: 2,
    validityEndDate: TOMORROW,
  });

  // Run 1: Alice initiates contact with Bob. Bob decrypts message.
  const plaintext1 = bufferToArray(Buffer.from('Hi. My name is Alice.'));
  const encryptionResult1 = await cms.encrypt(plaintext1, bobDhCertificate);
  const decryptionResult1 = await cms.decrypt(
    encryptionResult1.envelopedDataSerialized,
    bobDhKeyPair.privateKey,
    bobDhCertificate,
  );
  expectBuffersToEqual(decryptionResult1.plaintext, plaintext1);

  // Run 2: Bob replies to Alice. They have one DH key pair each.
  const plaintext2 = bufferToArray(Buffer.from('Hi, Alice. My name is Bob.'));
  const aliceDhCert1 = await issueInitialDHKeyCertificate({
    dhPublicKey: await getDhPublicKey(decryptionResult1.dhPublicKeyDer as ArrayBuffer),
    nodeCertificate,
    nodePrivateKey: nodeKeyPair.privateKey,
    serialNumber: 3,
    validityEndDate: TOMORROW,
  });
  const encryptionResult2 = await cms.encrypt(plaintext2, aliceDhCert1);
  const decryptionResult2 = await cms.decrypt(
    encryptionResult2.envelopedDataSerialized,
    encryptionResult1.dhPrivateKey as CryptoKey,
    aliceDhCert1,
  );
  expectBuffersToEqual(decryptionResult2.plaintext, plaintext2);

  // Run 3: Alice replies to Bob. Alice has two DH key pairs and Bob just one.
  const plaintext3 = bufferToArray(Buffer.from('Nice to meet you, Bob.'));
  const bobDhCert2 = await issueInitialDHKeyCertificate({
    dhPublicKey: await getDhPublicKey(decryptionResult2.dhPublicKeyDer as ArrayBuffer),
    nodeCertificate,
    nodePrivateKey: nodeKeyPair.privateKey,
    serialNumber: 4,
    validityEndDate: TOMORROW,
  });
  const encryptResult3 = await cms.encrypt(plaintext3, bobDhCert2);
  const decryptionResult3 = await cms.decrypt(
    encryptResult3.envelopedDataSerialized,
    encryptionResult2.dhPrivateKey as CryptoKey,
    bobDhCert2,
  );
  expectBuffersToEqual(decryptionResult3.plaintext, plaintext3);
});

async function getDhPublicKey(dhPublicKeyDer: ArrayBuffer): Promise<CryptoKey> {
  return cryptoEngine.importKey(
    'spki',
    dhPublicKeyDer,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    [],
  );
}
