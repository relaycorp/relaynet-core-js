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
import * as oids from '../../oids';
import { issueInitialDHKeyCertificate } from '../../pki';
import { derSerializePublicKey, generateECDHKeyPair, generateRSAKeyPair } from '../keys';
import Certificate from '../x509/Certificate';
import { deserializeContentInfo } from './_test_utils';
import CMSError from './CMSError';
import {
  EncryptionOptions,
  EnvelopedData,
  SessionEnvelopedData,
  SessionlessEnvelopedData,
  SessionOriginatorKey,
} from './envelopedData';

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

// For sessionless tests:
let nodePrivateKey: CryptoKey;
let nodeCertificate: Certificate;
beforeAll(async () => {
  const nodeKeyPair = await generateRSAKeyPair();
  nodePrivateKey = nodeKeyPair.privateKey;
  nodeCertificate = await generateStubCert({
    attributes: { isCA: true },
    issuerPrivateKey: nodePrivateKey,
    subjectPublicKey: nodeKeyPair.publicKey,
  });
});

// For channel session tests:
let bobDhPrivateKey: CryptoKey;
let bobDhPublicKey: CryptoKey;
let bobDhCertificate: Certificate;
beforeAll(async () => {
  const bobDhKeyPair = await generateECDHKeyPair();
  bobDhPrivateKey = bobDhKeyPair.privateKey;
  bobDhPublicKey = bobDhKeyPair.publicKey;
  bobDhCertificate = await issueInitialDHKeyCertificate({
    issuerCertificate: nodeCertificate,
    issuerPrivateKey: nodePrivateKey,
    subjectPublicKey: bobDhPublicKey,
    validityEndDate: TOMORROW,
  });
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('EnvelopedData', () => {
  describe('serialize', () => {
    test('EnvelopedData value should be wrapped in ContentInfo', async () => {
      const envelopedData = await SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);

      const envelopedDataSerialized = envelopedData.serialize();

      const contentInfo = deserializeContentInfo(envelopedDataSerialized);
      expect(contentInfo.contentType).toEqual(oids.CMS_ENVELOPED_DATA);
      expect(contentInfo.content).toBeInstanceOf(asn1js.Sequence);
    });
  });

  describe('deserialize', () => {
    test('Non-DER-encoded values should be refused', () => {
      const invalidDer = bufferToArray(Buffer.from('nope.jpeg'));
      expect(() => EnvelopedData.deserialize(invalidDer)).toThrowWithMessage(
        CMSError,
        'Could not deserialize CMS ContentInfo: Value is not DER-encoded',
      );
    });

    test('Outer value should be a CMS ContentInfo', () => {
      const asn1Value = new asn1js.Integer({ value: 3 });
      const derValue = asn1Value.toBER(false);

      expect(() => EnvelopedData.deserialize(derValue)).toThrowWithMessage(
        CMSError,
        /^Could not deserialize CMS ContentInfo: /,
      );
    });

    test('OID of inner value should be that of EnvelopedData', async () => {
      const envelopedData = await SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);
      const contentInfo = new pkijs.ContentInfo({
        content: envelopedData.pkijsEnvelopedData.toSchema(),
        contentType: '1.2',
      });
      const contentInfoSerialized = contentInfo.toSchema().toBER(false);

      expect(() => EnvelopedData.deserialize(contentInfoSerialized)).toThrowWithMessage(
        CMSError,
        'ContentInfo does not wrap an EnvelopedData value (got OID 1.2)',
      );
    });

    test('Inner value should be a valid EnvelopedData', async () => {
      const contentInfo = new pkijs.ContentInfo({
        content: new asn1js.Integer({ value: 3 }),
        contentType: oids.CMS_ENVELOPED_DATA,
      });
      const contentInfoSerialized = contentInfo.toSchema().toBER(false);

      expect(() => EnvelopedData.deserialize(contentInfoSerialized)).toThrowWithMessage(
        CMSError,
        /^Invalid EnvelopedData value: /,
      );
    });

    test('An EnvelopedData with zero recipientInfos should be refused', () => {
      const pkijsEnvelopedData = new pkijs.EnvelopedData();
      pkijsEnvelopedData.recipientInfos = [];
      const contentInfo = new pkijs.ContentInfo({
        content: pkijsEnvelopedData.toSchema(),
        contentType: oids.CMS_ENVELOPED_DATA,
      });
      const contentInfoSerialized = contentInfo.toSchema().toBER(false);

      expect(() => EnvelopedData.deserialize(contentInfoSerialized)).toThrowWithMessage(
        CMSError,
        /^Invalid EnvelopedData value:/,
      );
    });

    test('An EnvelopedData with multiple recipientInfos should be refused', async () => {
      const envelopedData = await SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);
      envelopedData.pkijsEnvelopedData.addRecipientByCertificate(
        nodeCertificate.pkijsCertificate,
        {},
        1,
      );
      const contentInfo = new pkijs.ContentInfo({
        content: envelopedData.pkijsEnvelopedData.toSchema(),
        contentType: oids.CMS_ENVELOPED_DATA,
      });
      const contentInfoSerialized = contentInfo.toSchema().toBER(false);

      expect(() => EnvelopedData.deserialize(contentInfoSerialized)).toThrowWithMessage(
        CMSError,
        'EnvelopedData must have exactly one RecipientInfo (got 2)',
      );
    });

    test('KeyTransRecipientInfo should result in SessionlessEnvelopedData instance', async () => {
      const originalEnvelopedData = await SessionlessEnvelopedData.encrypt(
        plaintext,
        nodeCertificate,
      );
      const envelopedDataSerialized = originalEnvelopedData.serialize();

      const envelopedData = EnvelopedData.deserialize(envelopedDataSerialized);
      expect(envelopedData).toBeInstanceOf(SessionlessEnvelopedData);
      expectAsn1ValuesToBeEqual(
        originalEnvelopedData.pkijsEnvelopedData.toSchema(),
        envelopedData.pkijsEnvelopedData.toSchema(),
      );
    });

    test('A KeyAgreeRecipientInfo should result in a SessionEnvelopedData instance', async () => {
      const { envelopedData } = await SessionEnvelopedData.encrypt(plaintext, bobDhCertificate);
      const envelopedDataSerialized = envelopedData.serialize();

      const envelopedDataDeserialized = EnvelopedData.deserialize(envelopedDataSerialized);
      expect(envelopedDataDeserialized).toBeInstanceOf(SessionEnvelopedData);
      expectAsn1ValuesToBeEqual(
        envelopedDataDeserialized.pkijsEnvelopedData.toSchema(),
        envelopedData.pkijsEnvelopedData.toSchema(),
      );
    });

    test('An unsupported RecipientInfo should be refused', async () => {
      const unsupportedEnvelopedData = await SessionlessEnvelopedData.encrypt(
        plaintext,
        nodeCertificate,
      );
      const unsupportedEnvelopedDataSerialized = unsupportedEnvelopedData.serialize();

      jest
        .spyOn(pkijs.RecipientInfo.prototype, 'fromSchema')
        .mockImplementationOnce(function(this: pkijs.RecipientInfo): void {
          this.variant = 3;
        });
      expect(() =>
        EnvelopedData.deserialize(unsupportedEnvelopedDataSerialized),
      ).toThrowWithMessage(CMSError, 'Unsupported RecipientInfo (variant: 3)');
    });
  });
});

describe('SessionlessEnvelopedData', () => {
  describe('encrypt', () => {
    describe('RecipientInfo', () => {
      test('RecipientInfo should be of type KeyTransRecipientInfo', async () => {
        const envelopedData = await SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);

        expect(envelopedData.pkijsEnvelopedData.recipientInfos[0].value).toBeInstanceOf(
          pkijs.KeyTransRecipientInfo,
        );
      });

      test('KeyTransRecipientInfo should use issuerAndSerialNumber choice', async () => {
        const envelopedData = await SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);

        const keyTransRecipientInfo = envelopedData.pkijsEnvelopedData.recipientInfos[0].value;
        expect(keyTransRecipientInfo.version).toEqual(0);
        expect(keyTransRecipientInfo.rid).toBeInstanceOf(pkijs.IssuerAndSerialNumber);
        expectPkijsValuesToBeEqual(
          keyTransRecipientInfo.rid.issuer,
          nodeCertificate.pkijsCertificate.issuer,
        );
        expectAsn1ValuesToBeEqual(
          keyTransRecipientInfo.rid.serialNumber,
          nodeCertificate.pkijsCertificate.serialNumber,
        );
      });

      test('KeyTransRecipientInfo should use RSA-OAEP', async () => {
        const envelopedData = await SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);

        const keyTransRecipientInfo = envelopedData.pkijsEnvelopedData.recipientInfos[0].value;
        expect(keyTransRecipientInfo.keyEncryptionAlgorithm.algorithmId).toEqual(OID_RSA_OAEP);
      });

      test('RSA-OAEP should be used with SHA-256', async () => {
        const envelopedData = await SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);

        const keyTransRecipientInfo = envelopedData.pkijsEnvelopedData.recipientInfos[0].value;
        const algorithmParams = new pkijs.RSAESOAEPParams({
          schema: keyTransRecipientInfo.keyEncryptionAlgorithm.algorithmParams,
        });
        expect(algorithmParams.hashAlgorithm.algorithmId).toEqual(OID_SHA256);
      });
    });

    describeEncryptedContentInfoEncryption(async (options?: EncryptionOptions) => {
      const envelopedData = await SessionlessEnvelopedData.encrypt(
        plaintext,
        nodeCertificate,
        options,
      );
      return envelopedData.serialize();
    });
  });

  describe('decrypt', () => {
    test('Decryption with the wrong private key should fail', async () => {
      const differentCertificate = await generateStubCert();
      const envelopedData = await SessionlessEnvelopedData.encrypt(plaintext, differentCertificate);

      expect.hasAssertions();
      try {
        await envelopedData.decrypt(nodePrivateKey);
      } catch (error) {
        expect(error).toBeInstanceOf(CMSError);
        expect(error.message).toStartWith(`Decryption failed: ${error.cause().message}`);
      }
    });

    test('Decryption should succeed with the right private key', async () => {
      const envelopedData = await SessionlessEnvelopedData.encrypt(plaintext, nodeCertificate);
      const actualPlaintext = await envelopedData.decrypt(nodePrivateKey);
      expectBuffersToEqual(actualPlaintext, plaintext);
    });
  });
});

describe('SessionEnvelopedData', () => {
  describe('encrypt', () => {
    test('Result should include generated (EC)DH private key', async () => {
      jest.spyOn(pkijs.EnvelopedData.prototype, 'encrypt');
      const { dhPrivateKey } = await SessionEnvelopedData.encrypt(plaintext, bobDhCertificate);

      const pkijsEncryptCall = getMockContext(pkijs.EnvelopedData.prototype.encrypt).results[0];
      expect(dhPrivateKey).toBe((await pkijsEncryptCall.value)[0].ecdhPrivateKey);
    });

    test('Originator should include curve name in the algorithm parameters', async () => {
      const { envelopedData } = await SessionEnvelopedData.encrypt(plaintext, bobDhCertificate);

      const algorithm =
        envelopedData.pkijsEnvelopedData.recipientInfos[0].value.originator.value.algorithm;
      expect(algorithm).toHaveProperty('algorithmParams');
      expect(algorithm.algorithmParams.valueBlock.toString()).toEqual(OID_ECDH_P256);
    });

    test('Generated (EC)DH key id should be output and included in unprotectedAttrs', async () => {
      const { envelopedData, dhKeyId } = await SessionEnvelopedData.encrypt(
        plaintext,
        bobDhCertificate,
      );

      expect(dhKeyId).toBeInstanceOf(ArrayBuffer);
      expect(dhKeyId).toHaveProperty('byteLength', 8);

      expect(envelopedData.pkijsEnvelopedData.unprotectedAttrs).toHaveLength(1);
      const dhKeyIdAttribute = (envelopedData.pkijsEnvelopedData
        .unprotectedAttrs as readonly pkijs.Attribute[])[0];
      expect(dhKeyIdAttribute).toHaveProperty(
        'type',
        OID_RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
      );
      // @ts-ignore
      expectBuffersToEqual(dhKeyIdAttribute.values[0].valueBlock.valueHex, dhKeyId);
    });

    test('Originator key should be acceptable in lieu of certificate', async () => {
      jest.spyOn(pkijs.EnvelopedData.prototype, 'encrypt');
      const bobOriginatorKey: SessionOriginatorKey = {
        keyId: Buffer.from('key id'),
        publicKey: bobDhPublicKey,
      };
      const { envelopedData } = await SessionEnvelopedData.encrypt(plaintext, bobOriginatorKey);

      expect(envelopedData.getRecipientKeyId()).toEqual(bobOriginatorKey.keyId);

      const recipientInfo = envelopedData.pkijsEnvelopedData.recipientInfos[0];
      const recipientCertificate = recipientInfo.value.recipientCertificate;
      const recipientPublicKey = recipientCertificate.subjectPublicKeyInfo.toSchema().toBER(false);
      expectBuffersToEqual(
        await derSerializePublicKey(bobOriginatorKey.publicKey),
        Buffer.from(recipientPublicKey),
      );
    });

    describeEncryptedContentInfoEncryption(async (options?: EncryptionOptions) => {
      const { envelopedData } = await SessionEnvelopedData.encrypt(
        plaintext,
        bobDhCertificate,
        options,
      );
      return envelopedData.serialize();
    });
  });

  describe('getOriginatorKey', () => {
    let envelopedData: SessionEnvelopedData;
    beforeEach(async () => {
      const encryptionResult = await SessionEnvelopedData.encrypt(plaintext, bobDhCertificate);
      envelopedData = encryptionResult.envelopedData;
    });

    describe('keyId', () => {
      test('Originator DH public key id should be returned', async () => {
        const { keyId } = await envelopedData.getOriginatorKey();

        const unprotectedAttrs = envelopedData.pkijsEnvelopedData
          .unprotectedAttrs as readonly pkijs.Attribute[];
        const dhKeyIdAttribute = unprotectedAttrs[0];
        expect(keyId).toEqual(
          // @ts-ignore
          Buffer.from(dhKeyIdAttribute.values[0].valueBlock.valueHex),
        );
      });

      test('Call should fail if unprotectedAttrs is missing', async () => {
        envelopedData.pkijsEnvelopedData.unprotectedAttrs = undefined;

        await expectPromiseToReject(
          envelopedData.getOriginatorKey(),
          new CMSError('unprotectedAttrs must be present when using channel session'),
        );
      });

      test('Call should fail if unprotectedAttrs is present but empty', async () => {
        envelopedData.pkijsEnvelopedData.unprotectedAttrs = [];

        await expectPromiseToReject(
          envelopedData.getOriginatorKey(),
          new CMSError('unprotectedAttrs must be present when using channel session'),
        );
      });

      test('Call should fail if originator key id is missing', async () => {
        const otherAttribute = new pkijs.Attribute({
          type: '1.2.3.4',
          values: [new asn1js.Integer({ value: 2 })],
        });
        envelopedData.pkijsEnvelopedData.unprotectedAttrs = [otherAttribute];

        await expectPromiseToReject(
          envelopedData.getOriginatorKey(),
          new CMSError('unprotectedAttrs does not contain originator key id'),
        );
      });

      test('Call should fail if attribute for originator key id is empty', async () => {
        const invalidAttribute = new pkijs.Attribute({
          type: OID_RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
          values: [],
        });
        envelopedData.pkijsEnvelopedData.unprotectedAttrs = [invalidAttribute];

        await expectPromiseToReject(
          envelopedData.getOriginatorKey(),
          new CMSError('Originator key id attribute must have exactly one value (got 0)'),
        );
      });

      test('Call should fail if attribute for originator key id is multi-valued', async () => {
        const invalidAttribute = new pkijs.Attribute({
          type: OID_RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
          values: [new asn1js.Integer({ value: 1 }), new asn1js.Integer({ value: 2 })],
        });
        envelopedData.pkijsEnvelopedData.unprotectedAttrs = [invalidAttribute];

        await expectPromiseToReject(
          envelopedData.getOriginatorKey(),
          new CMSError('Originator key id attribute must have exactly one value (got 2)'),
        );
      });
    });

    describe('publicKey', () => {
      test('Originator DH public key should be returned if it is valid', async () => {
        const { publicKey } = await envelopedData.getOriginatorKey();

        const recipientInfo = envelopedData.pkijsEnvelopedData.recipientInfos[0];
        const expectedPublicKeyDer = recipientInfo.value.originator.value.toSchema().toBER(false);
        expectBuffersToEqual(
          Buffer.from(expectedPublicKeyDer),
          await derSerializePublicKey(publicKey),
        );
      });

      test('Call should fail if RecipientInfo is not KeyAgreeRecipientInfo', async () => {
        envelopedData.pkijsEnvelopedData.recipientInfos[0].variant = 3;

        await expectPromiseToReject(
          envelopedData.getOriginatorKey(),
          new CMSError('Expected KeyAgreeRecipientInfo (got variant: 3)'),
        );
      });
    });
  });

  test('getRecipientKeyId() should return the recipient key id', async () => {
    const { envelopedData } = await SessionEnvelopedData.encrypt(plaintext, bobDhCertificate);

    const actualKeyId = envelopedData.getRecipientKeyId();
    expect(actualKeyId).toEqual(bobDhCertificate.getSerialNumber());
  });

  describe('decrypt', () => {
    test('Decryption with the wrong private key should fail', async () => {
      const differentDhKeyPair = await generateECDHKeyPair();
      const { envelopedData } = await SessionEnvelopedData.encrypt(plaintext, bobDhCertificate);

      expect.hasAssertions();
      try {
        await envelopedData.decrypt(differentDhKeyPair.privateKey);
      } catch (error) {
        expect(error).toBeInstanceOf(CMSError);
        expect(error.message).toStartWith(`Decryption failed: ${error.cause().message}`);
      }
    });

    test('Decryption should succeed with the right private key', async () => {
      const { envelopedData } = await SessionEnvelopedData.encrypt(plaintext, bobDhCertificate);

      const decryptedPlaintext = await envelopedData.decrypt(bobDhPrivateKey);
      expectBuffersToEqual(decryptedPlaintext, plaintext);
    });

    test('Recipient DH certificate should be faked to set the key algorithm', async () => {
      const { envelopedData } = await SessionEnvelopedData.encrypt(plaintext, bobDhCertificate);

      jest.spyOn(pkijs.EnvelopedData.prototype, 'decrypt');
      await envelopedData.decrypt(bobDhPrivateKey);

      const pkijsDecryptCall = getMockContext(pkijs.EnvelopedData.prototype.decrypt).calls[0];
      const pkijsDecryptCallArgs = pkijsDecryptCall[1];
      const actualAlgorithm =
        pkijsDecryptCallArgs.recipientCertificate.subjectPublicKeyInfo.algorithm;
      const expectedAlgorithm = bobDhCertificate.pkijsCertificate.subjectPublicKeyInfo.algorithm;
      expect(actualAlgorithm.algorithmParams.valueBlock.toString()).toEqual(
        expectedAlgorithm.algorithmParams.valueBlock.toString(),
      );
    });

    test('Decryption with mismatching key algorithms should fail', async () => {
      // This is a safeguard for the workaround to avoid having to pass the recipientCertificate
      // to PKI.js EnvelopedData.encrypt().
      const { privateKey } = await generateECDHKeyPair('P-384');
      expect((privateKey.algorithm as EcKeyAlgorithm).namedCurve).not.toEqual(
        (bobDhPrivateKey.algorithm as EcKeyAlgorithm).namedCurve,
      );
      const { envelopedData } = await SessionEnvelopedData.encrypt(plaintext, bobDhCertificate);

      await expectPromiseToReject(
        envelopedData.decrypt(privateKey),
        // Leaving the typos unchanged because they come from a dependency of PKI.js and I
        // want to make sure this scenario fails for the expected reason.
        new CMSError('Decryption failed: Named corves of EC keys are not equals'),
      );
    });
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
        encryptFunc({ aesKeySize: 512 }),
        new CMSError('Invalid AES key size (512)'),
      );
    });
  });
}

function deserializeEnvelopedData(contentInfoDer: ArrayBuffer): pkijs.EnvelopedData {
  const contentInfo = deserializeContentInfo(contentInfoDer);
  return new pkijs.EnvelopedData({ schema: contentInfo.content });
}
