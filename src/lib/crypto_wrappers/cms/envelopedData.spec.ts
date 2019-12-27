// tslint:disable:no-let no-object-mutation
import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import * as pkijs from 'pkijs';

import {
  expectAsn1ValuesToBeEqual,
  expectBuffersToEqual,
  expectPkijsValuesToBeEqual,
  expectPromiseToReject,
  generateStubCert,
  getMockContext,
} from '../../_test_utils';
import { issueInitialDHKeyCertificate } from '../../nodes';
import * as oids from '../../oids';
import { generateECDHKeyPair, generateRSAKeyPair } from '../keyGenerators';
import Certificate from '../x509/Certificate';
import { deserializeContentInfo } from './_test_utils';
import CMSError from './CMSError';
import { decrypt, encrypt, EncryptionOptions, EncryptionResult } from './envelopedData';

const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_AES_GCM_128 = '2.16.840.1.101.3.4.1.6';
const OID_AES_GCM_192 = '2.16.840.1.101.3.4.1.26';
const OID_AES_GCM_256 = '2.16.840.1.101.3.4.1.46';
const OID_RSA_OAEP = '1.2.840.113549.1.1.7';
const OID_ECDH_P256 = '1.2.840.10045.3.1.7';
const OID_RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER = '0.4.0.127.0.17.0.1.0';

const plaintext = bufferToArray(Buffer.from('Winter is coming'));

const TOMORROW = new Date();
TOMORROW.setDate(TOMORROW.getDate() + 1);

let privateKey: CryptoKey;
let certificate: Certificate;
beforeAll(async () => {
  const keyPair = await generateRSAKeyPair();
  privateKey = keyPair.privateKey;
  certificate = await generateStubCert({
    issuerPrivateKey: privateKey,
    subjectPublicKey: keyPair.publicKey,
  });
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('EnvelopedData', () => {
  describe('serialize', () => {
    test('EnvelopedData value should be wrapped in ContentInfo', async () => {
      const { envelopedDataSerialized } = await encrypt(plaintext, certificate);

      const contentInfo = deserializeContentInfo(envelopedDataSerialized);
      expect(contentInfo.contentType).toEqual(oids.CMS_ENVELOPED_DATA);
      expect(contentInfo.content).toBeInstanceOf(asn1js.Sequence);
    });
  });
});

describe('SessionlessEnvelopedData', () => {
  describe('encrypt', () => {
    describe('RecipientInfo', () => {
      test('RecipientInfo should be of type KeyTransRecipientInfo', async () => {
        const { envelopedDataSerialized } = await encrypt(plaintext, certificate);

        const envelopedData = deserializeEnvelopedData(envelopedDataSerialized);
        expect(envelopedData.recipientInfos[0].value).toBeInstanceOf(pkijs.KeyTransRecipientInfo);
      });

      test('KeyTransRecipientInfo should use issuerAndSerialNumber choice', async () => {
        const { envelopedDataSerialized } = await encrypt(plaintext, certificate);

        const envelopedData = deserializeEnvelopedData(envelopedDataSerialized);
        const keyTransRecipientInfo = envelopedData.recipientInfos[0].value;
        expect(keyTransRecipientInfo.version).toEqual(0);
        expect(keyTransRecipientInfo.rid).toBeInstanceOf(pkijs.IssuerAndSerialNumber);
        expectPkijsValuesToBeEqual(
          keyTransRecipientInfo.rid.issuer,
          certificate.pkijsCertificate.issuer,
        );
        expectAsn1ValuesToBeEqual(
          keyTransRecipientInfo.rid.serialNumber,
          certificate.pkijsCertificate.serialNumber,
        );
      });

      test('KeyTransRecipientInfo should use RSA-OAEP', async () => {
        const { envelopedDataSerialized } = await encrypt(plaintext, certificate);

        const envelopedData = deserializeEnvelopedData(envelopedDataSerialized);
        const keyTransRecipientInfo = envelopedData.recipientInfos[0].value;
        expect(keyTransRecipientInfo.keyEncryptionAlgorithm.algorithmId).toEqual(OID_RSA_OAEP);
      });

      test('RSA-OAEP should be used with SHA-256', async () => {
        const { envelopedDataSerialized } = await encrypt(plaintext, certificate);

        const envelopedData = deserializeEnvelopedData(envelopedDataSerialized);
        const keyTransRecipientInfo = envelopedData.recipientInfos[0].value;
        const algorithmParams = new pkijs.RSAESOAEPParams({
          schema: keyTransRecipientInfo.keyEncryptionAlgorithm.algorithmParams,
        });
        expect(algorithmParams.hashAlgorithm.algorithmId).toEqual(OID_SHA256);
      });
    });

    describeEncryptedContentInfoEncryption(
      async (options?: EncryptionOptions) =>
        (await encrypt(plaintext, certificate, options)).envelopedDataSerialized,
    );
  });
});

describe('SessionEnvelopedData', () => {
  let bobDhCertificate: Certificate;
  beforeAll(async () => {
    const nodeKeyPair = await generateRSAKeyPair();
    const nodeCertificate = await generateStubCert({
      attributes: { isCA: true, serialNumber: 1 },
      issuerPrivateKey: nodeKeyPair.privateKey,
      subjectPublicKey: nodeKeyPair.publicKey,
    });

    const bobDhKeyPair = await generateECDHKeyPair();
    bobDhCertificate = await issueInitialDHKeyCertificate({
      dhPublicKey: bobDhKeyPair.publicKey,
      nodeCertificate,
      nodePrivateKey: nodeKeyPair.privateKey,
      serialNumber: 2,
      validityEndDate: TOMORROW,
    });
  });

  describe('encrypt', () => {
    test('Result should include generated (EC)DH private key', async () => {
      jest.spyOn(pkijs.EnvelopedData.prototype, 'encrypt');
      const { dhPrivateKey } = await encrypt(plaintext, bobDhCertificate);

      const pkijsEncryptCall = getMockContext(pkijs.EnvelopedData.prototype.encrypt).results[0];
      expect(dhPrivateKey).toBe((await pkijsEncryptCall.value)[0].ecdhPrivateKey);
    });

    test('Originator should include curve name in the algorithm parameters', async () => {
      const { envelopedDataSerialized } = await encrypt(plaintext, bobDhCertificate);

      const envelopedData = await deserializeEnvelopedData(envelopedDataSerialized);
      const algorithm = envelopedData.recipientInfos[0].value.originator.value.algorithm;
      expect(algorithm).toHaveProperty('algorithmParams');
      expect(algorithm.algorithmParams.valueBlock.toString()).toEqual(OID_ECDH_P256);
    });

    test('Generated (EC)DH key id should be output and included in unprotectedAttrs', async () => {
      const { envelopedDataSerialized, dhKeyId } = await encrypt(plaintext, bobDhCertificate);

      // Serial number would be 0 if the input to getRandomValues() was initialized but the
      // function was not called. This is somewhat brittle but we can't use spyOn() because that
      // wouldn't call the spied function, which is also used by EnvelopedData.encrypt().
      expect(dhKeyId).not.toEqual(0);

      const envelopedData = await deserializeEnvelopedData(envelopedDataSerialized);
      expect(envelopedData.unprotectedAttrs).toHaveLength(1);
      const dhKeyIdAttribute = (envelopedData.unprotectedAttrs as readonly pkijs.Attribute[])[0];
      expect(dhKeyIdAttribute).toHaveProperty(
        'type',
        OID_RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
      );
      expect(
        // @ts-ignore
        dhKeyIdAttribute.values[0].valueBlock.toString(),
      ).toEqual((dhKeyId as number).toString());
    });

    describeEncryptedContentInfoEncryption(
      async (options?: EncryptionOptions) =>
        (await encrypt(plaintext, bobDhCertificate, options)).envelopedDataSerialized,
    );
  });
});

function describeEncryptedContentInfoEncryption(
  encryptFunc: (opts?: EncryptionOptions) => Promise<ArrayBuffer>,
): void {
  describe('EncryptedContentInfo', () => {
    test('AES-GCM-128 should be used by default', async () => {
      const envelopedDataSerialized = await encryptFunc();

      const envelopedData = deserializeEnvelopedData(envelopedDataSerialized);
      expect(envelopedData.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId).toEqual(
        OID_AES_GCM_128,
      );
    });

    test.each([
      [192, OID_AES_GCM_192],
      [256, OID_AES_GCM_256],
    ])('AES-GCM-%s should also be supported', async (aesKeySize, expectedOid) => {
      const envelopedDataSerialized = await encryptFunc({ aesKeySize: aesKeySize as number });

      const envelopedData = deserializeEnvelopedData(envelopedDataSerialized);
      expect(envelopedData.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId).toEqual(
        expectedOid,
      );
    });

    test('Key sizes other than 128, 192 and 256 should be refused', async () => {
      await expectPromiseToReject(
        encrypt(plaintext, certificate, { aesKeySize: 512 }),
        new CMSError('Invalid AES key size (512)'),
      );
    });
  });
}

describe('decrypt', () => {
  test('An error should be thrown if input is not DER encoded', async () => {
    const invalidDer = bufferToArray(Buffer.from('nope.jpeg'));
    await expectPromiseToReject(
      decrypt(invalidDer, privateKey),
      new Error('Value is not DER-encoded'),
    );
  });

  test('A well-formed but invalid ciphertext should be refused', async () => {
    const differentCertificate = await generateStubCert();
    const { envelopedDataSerialized } = await encrypt(plaintext, differentCertificate);

    expect.hasAssertions();
    try {
      await decrypt(envelopedDataSerialized, privateKey);
    } catch (error) {
      expect(error).toBeInstanceOf(CMSError);
      expect(error.message).toStartWith(`Decryption failed: ${error.cause().message}`);
    }
  });

  test('Decryption should succeed with the right private key', async () => {
    const { envelopedDataSerialized } = await encrypt(plaintext, certificate);
    const decryptionResult = await decrypt(envelopedDataSerialized, privateKey);
    expectBuffersToEqual(decryptionResult.plaintext, plaintext);
  });

  describe('Key agreement', () => {
    let encryptionResult: EncryptionResult;
    let bobDhPrivateKey: CryptoKey;
    let bobDhCertificate: Certificate;
    beforeAll(async () => {
      const nodeKeyPair = await generateRSAKeyPair();
      const nodeCertificate = await generateStubCert({
        attributes: { isCA: true, serialNumber: 1 },
        issuerPrivateKey: nodeKeyPair.privateKey,
        subjectPublicKey: nodeKeyPair.publicKey,
      });

      const bobDhKeyPair = await generateECDHKeyPair();
      bobDhPrivateKey = bobDhKeyPair.privateKey;
      const tomorrow = new Date();
      tomorrow.setDate(tomorrow.getDate() + 1);
      bobDhCertificate = await issueInitialDHKeyCertificate({
        dhPublicKey: bobDhKeyPair.publicKey,
        nodeCertificate,
        nodePrivateKey: nodeKeyPair.privateKey,
        serialNumber: 2,
        validityEndDate: tomorrow,
      });

      encryptionResult = await encrypt(plaintext, bobDhCertificate);
    });

    test('Recipient DH public key should be used to calculate shared secret', async () => {
      jest.spyOn(pkijs.EnvelopedData.prototype, 'decrypt');

      await decrypt(encryptionResult.envelopedDataSerialized, bobDhPrivateKey, bobDhCertificate);

      const pkijsDecryptCall = getMockContext(pkijs.EnvelopedData.prototype.decrypt).calls[0];
      const pkijsDecryptCallArgs = pkijsDecryptCall[1];
      expect(pkijsDecryptCallArgs).toHaveProperty(
        'recipientCertificate',
        bobDhCertificate.pkijsCertificate,
      );
    });

    test('Originator DH public key id should be output', async () => {
      const { dhKeyId } = await decrypt(
        encryptionResult.envelopedDataSerialized,
        bobDhPrivateKey,
        bobDhCertificate,
      );

      const envelopedData = deserializeEnvelopedData(encryptionResult.envelopedDataSerialized);
      const dhKeyIdAttribute = (envelopedData.unprotectedAttrs as readonly pkijs.Attribute[])[0];
      expect(dhKeyId).toEqual(
        // @ts-ignore
        parseInt(dhKeyIdAttribute.values[0].valueBlock.toString(), 10),
      );
    });

    test('Decryption should fail if unprotectedAttrs is missing', async () => {
      jest
        .spyOn(pkijs.EnvelopedData.prototype, 'decrypt')
        .mockImplementationOnce(async function(this: pkijs.EnvelopedData): Promise<ArrayBuffer> {
          this.unprotectedAttrs = undefined;
          return plaintext;
        });

      await expectPromiseToReject(
        decrypt(encryptionResult.envelopedDataSerialized, bobDhPrivateKey, bobDhCertificate),
        new CMSError('unprotectedAttrs must be present when using channel session'),
      );
    });

    test('Decryption should fail if unprotectedAttrs is present but empty', async () => {
      jest
        .spyOn(pkijs.EnvelopedData.prototype, 'decrypt')
        .mockImplementation(async function(this: pkijs.EnvelopedData): Promise<ArrayBuffer> {
          this.unprotectedAttrs = [];
          return plaintext;
        });

      await expectPromiseToReject(
        decrypt(encryptionResult.envelopedDataSerialized, bobDhPrivateKey, bobDhCertificate),
        new CMSError('unprotectedAttrs must be present when using channel session'),
      );
    });

    test('Decryption should fail if originator key id is missing', async () => {
      const invalidAttribute = new pkijs.Attribute({
        type: '1.2.3.4',
        values: [new asn1js.Integer({ value: 2 })],
      });
      jest
        .spyOn(pkijs.EnvelopedData.prototype, 'decrypt')
        .mockImplementation(async function(this: pkijs.EnvelopedData): Promise<ArrayBuffer> {
          this.unprotectedAttrs = [invalidAttribute];
          return plaintext;
        });

      await expectPromiseToReject(
        decrypt(encryptionResult.envelopedDataSerialized, bobDhPrivateKey, bobDhCertificate),
        new CMSError('unprotectedAttrs does not contain originator key id'),
      );
    });

    test('Decryption should fail if attribute for originator key id is empty', async () => {
      const invalidAttribute = new pkijs.Attribute({
        type: OID_RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
        values: [],
      });
      jest
        .spyOn(pkijs.EnvelopedData.prototype, 'decrypt')
        .mockImplementation(async function(this: pkijs.EnvelopedData): Promise<ArrayBuffer> {
          this.unprotectedAttrs = [invalidAttribute];
          return plaintext;
        });

      await expectPromiseToReject(
        decrypt(encryptionResult.envelopedDataSerialized, bobDhPrivateKey, bobDhCertificate),
        new CMSError('Originator key id attribute must have exactly one value (got 0)'),
      );
    });

    test('Decryption should fail if attribute for originator key id is multi-valued', async () => {
      const invalidAttribute = new pkijs.Attribute({
        type: OID_RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
        values: [new asn1js.Integer({ value: 1 }), new asn1js.Integer({ value: 2 })],
      });
      jest
        .spyOn(pkijs.EnvelopedData.prototype, 'decrypt')
        .mockImplementation(async function(this: pkijs.EnvelopedData): Promise<ArrayBuffer> {
          this.unprotectedAttrs = [invalidAttribute];
          return plaintext;
        });

      await expectPromiseToReject(
        decrypt(encryptionResult.envelopedDataSerialized, bobDhPrivateKey, bobDhCertificate),
        new CMSError('Originator key id attribute must have exactly one value (got 2)'),
      );
    });

    test('Originator DH public key should be output', async () => {
      const { dhPublicKeyDer } = await decrypt(
        encryptionResult.envelopedDataSerialized,
        bobDhPrivateKey,
        bobDhCertificate,
      );

      const envelopedData = deserializeEnvelopedData(encryptionResult.envelopedDataSerialized);
      const expectedPublicKey = envelopedData.recipientInfos[0].value.originator.value
        .toSchema()
        .toBER(false);
      expectBuffersToEqual(expectedPublicKey, dhPublicKeyDer as ArrayBuffer);
    });
  });
});

function deserializeEnvelopedData(contentInfoDer: ArrayBuffer): pkijs.EnvelopedData {
  const contentInfo = deserializeContentInfo(contentInfoDer);
  return new pkijs.EnvelopedData({ schema: contentInfo.content });
}
