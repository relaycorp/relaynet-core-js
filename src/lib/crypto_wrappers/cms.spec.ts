import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import { createHash } from 'crypto';
import * as pkijs from 'pkijs';

import {
  expectAsn1ValuesToBeEqual,
  expectPkijsValuesToBeEqual,
  expectPromiseToReject,
  generateStubCert,
  sha256Hex,
} from '../_test_utils';
import { deserializeDer } from '../_utils';
import * as oids from '../oids';
import * as cms from './cms';
import CMSError from './CMSError';
import { generateRSAKeyPair } from './keyGenerators';
import Certificate from './x509/Certificate';

const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_AES_GCM_128 = '2.16.840.1.101.3.4.1.6';
const OID_AES_GCM_192 = '2.16.840.1.101.3.4.1.26';
const OID_AES_GCM_256 = '2.16.840.1.101.3.4.1.46';
const OID_RSA_OAEP = '1.2.840.113549.1.1.7';

const plaintext = bufferToArray(Buffer.from('Winter is coming'));

// tslint:disable-next-line:no-let
let privateKey: CryptoKey;
// tslint:disable-next-line:no-let
let certificate: Certificate;
beforeAll(async () => {
  const keyPair = await generateRSAKeyPair();
  privateKey = keyPair.privateKey;
  certificate = await generateStubCert({
    issuerPrivateKey: privateKey,
    subjectPublicKey: keyPair.publicKey,
  });
});

describe('encrypt', () => {
  test('EnvelopedData value should be wrapped in ContentInfo', async () => {
    const contentInfoDer = await cms.encrypt(plaintext, certificate);

    const contentInfo = deserializeContentInfo(contentInfoDer);
    expect(contentInfo.contentType).toEqual(oids.CMS_ENVELOPED_DATA);
    expect(contentInfo.content).toBeInstanceOf(asn1js.Sequence);
  });

  describe('RecipientInfo', () => {
    test('There should only be one RecipientInfo', async () => {
      const contentInfoDer = await cms.encrypt(plaintext, certificate);

      const envelopedData = deserializeEnvelopedData(contentInfoDer);
      expect(envelopedData.recipientInfos).toHaveLength(1);
      expect(envelopedData.recipientInfos[0]).toBeInstanceOf(pkijs.RecipientInfo);
    });

    test('RecipientInfo should be of type KeyTransRecipientInfo', async () => {
      const contentInfoDer = await cms.encrypt(plaintext, certificate);

      const envelopedData = deserializeEnvelopedData(contentInfoDer);
      expect(envelopedData.recipientInfos[0].value).toBeInstanceOf(pkijs.KeyTransRecipientInfo);
    });

    test('KeyTransRecipientInfo should use issuerAndSerialNumber choice', async () => {
      const contentInfoDer = await cms.encrypt(plaintext, certificate);

      const envelopedData = deserializeEnvelopedData(contentInfoDer);
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
      const contentInfoDer = await cms.encrypt(plaintext, certificate);

      const envelopedData = deserializeEnvelopedData(contentInfoDer);
      const keyTransRecipientInfo = envelopedData.recipientInfos[0].value;
      expect(keyTransRecipientInfo.keyEncryptionAlgorithm.algorithmId).toEqual(OID_RSA_OAEP);
    });

    test('RSA-OAEP should be used with SHA-256', async () => {
      const contentInfoDer = await cms.encrypt(plaintext, certificate);

      const envelopedData = deserializeEnvelopedData(contentInfoDer);
      const keyTransRecipientInfo = envelopedData.recipientInfos[0].value;
      const algorithmParams = new pkijs.RSAESOAEPParams({
        schema: keyTransRecipientInfo.keyEncryptionAlgorithm.algorithmParams,
      });
      expect(algorithmParams.hashAlgorithm.algorithmId).toEqual(OID_SHA256);
    });
  });

  describe('EncryptedContentInfo', () => {
    test('AES-GCM-128 should be used by default', async () => {
      const contentInfoDer = await cms.encrypt(plaintext, certificate);

      const envelopedData = deserializeEnvelopedData(contentInfoDer);
      expect(envelopedData.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId).toEqual(
        OID_AES_GCM_128,
      );
    });

    test.each([[192, OID_AES_GCM_192], [256, OID_AES_GCM_256]])(
      'AES-GCM-%s should also be supported',
      async (aesKeySize, expectedOid) => {
        // @ts-ignore
        const contentInfoDer = await cms.encrypt(plaintext, certificate, {
          aesKeySize,
        });

        const envelopedData = deserializeEnvelopedData(contentInfoDer);
        expect(envelopedData.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId).toEqual(
          expectedOid,
        );
      },
    );

    test('Key sizes other than 128, 192 and 256 should be refused', async () => {
      await expectPromiseToReject(
        cms.encrypt(plaintext, certificate, { aesKeySize: 512 }),
        new CMSError('Invalid AES key size (512)'),
      );
    });
  });
});

describe('decrypt', () => {
  test('An error should be thrown if input is not DER encoded', async () => {
    const invalidDer = bufferToArray(Buffer.from('nope.jpeg'));
    await expectPromiseToReject(
      cms.decrypt(invalidDer, privateKey),
      new Error('Value is not DER-encoded'),
    );
  });

  test('A well-formed but invalid ciphertext should be refused', async () => {
    const differentCertificate = await generateStubCert();
    const ciphertext = await cms.encrypt(plaintext, differentCertificate);

    expect.hasAssertions();
    try {
      await cms.decrypt(ciphertext, privateKey);
    } catch (error) {
      expect(error).toBeInstanceOf(CMSError);
      expect(error.message).toStartWith('Decryption failed: ');
    }
  });

  test('Decryption should succeed with the right private key', async () => {
    const ciphertext = await cms.encrypt(plaintext, certificate);
    const actualPlaintext = await cms.decrypt(ciphertext, privateKey);
    expect(Buffer.from(actualPlaintext).equals(Buffer.from(plaintext))).toBeTrue();
  });
});

describe('sign', () => {
  test('SignedData value should be wrapped in ContentInfo', async () => {
    const contentInfoDer = await cms.sign(plaintext, privateKey, certificate);

    const contentInfo = deserializeContentInfo(contentInfoDer);
    expect(contentInfo.contentType).toEqual(oids.CMS_SIGNED_DATA);
    expect(contentInfo.content).toBeInstanceOf(asn1js.Sequence);
  });

  test('SignedData version should be 1', async () => {
    const contentInfoDer = await cms.sign(plaintext, privateKey, certificate);

    const pkijsSignedData = deserializeSignedData(contentInfoDer);
    expect(pkijsSignedData).toHaveProperty('version', 1);
  });

  describe('SignerInfo', () => {
    test('There should only be one SignerInfo', async () => {
      const contentInfoDer = await cms.sign(plaintext, privateKey, certificate);

      const pkijsSignedData = deserializeSignedData(contentInfoDer);
      expect(pkijsSignedData.signerInfos).toHaveLength(1);
      expect(pkijsSignedData.signerInfos[0]).toBeInstanceOf(pkijs.SignerInfo);
    });

    test('Version should be 1', async () => {
      const contentInfoDer = await cms.sign(plaintext, privateKey, certificate);

      const signerInfo = deserializeSignerInfo(contentInfoDer);
      expect(signerInfo).toHaveProperty('version', 1);
    });

    test('SignerIdentifier should be IssuerAndSerialNumber', async () => {
      const contentInfoDer = await cms.sign(plaintext, privateKey, certificate);

      const signerInfo = deserializeSignerInfo(contentInfoDer);
      expect(signerInfo.sid).toBeInstanceOf(pkijs.IssuerAndSerialNumber);
      expectPkijsValuesToBeEqual(signerInfo.sid.issuer, certificate.pkijsCertificate.issuer);
      expectAsn1ValuesToBeEqual(
        signerInfo.sid.serialNumber,
        certificate.pkijsCertificate.serialNumber,
      );
    });

    test('Signature should be detached', async () => {
      jest.spyOn(pkijs.SignedData.prototype, 'sign');
      const contentInfoDer = await cms.sign(plaintext, privateKey, certificate);

      const signedData = deserializeSignedData(contentInfoDer);
      expect(signedData.encapContentInfo).toBeInstanceOf(pkijs.EncapsulatedContentInfo);
      expect(signedData.encapContentInfo).toHaveProperty('eContentType', oids.CMS_DATA);
      expect(signedData.encapContentInfo).not.toHaveProperty('eContent');
    });

    describe('SignedAttributes', () => {
      test('Signed attributes should be present', async () => {
        const contentInfoDer = await cms.sign(plaintext, privateKey, certificate);

        const signerInfo = deserializeSignerInfo(contentInfoDer);
        expect(signerInfo.signedAttrs).toBeInstanceOf(pkijs.SignedAndUnsignedAttributes);
        expect(signerInfo.signedAttrs).toHaveProperty('type', 0);
      });

      test('Content type attribute should be set to CMS Data', async () => {
        const contentInfoDer = await cms.sign(plaintext, privateKey, certificate);

        const contentTypeAttribute = deserializeSignerInfoAttribute(
          contentInfoDer,
          oids.CMS_ATTR_CONTENT_TYPE,
        );
        // @ts-ignore
        expect(contentTypeAttribute.values).toHaveLength(1);
        expect(
          // @ts-ignore
          contentTypeAttribute.values[0].valueBlock.toString(),
        ).toEqual(oids.CMS_DATA);
      });

      test('Plaintext digest should be present', async () => {
        const contentInfoDer = await cms.sign(plaintext, privateKey, certificate);

        const digestAttribute = deserializeSignerInfoAttribute(
          contentInfoDer,
          oids.CMS_ATTR_DIGEST,
        );
        // @ts-ignore
        expect(digestAttribute.values).toHaveLength(1);
        expect(
          // @ts-ignore
          digestAttribute.values[0].valueBlock.valueHex,
        ).toBeTruthy();
      });
    });
  });

  describe('Attached certificates', () => {
    test('The signer certificate should not be attached', async () => {
      const contentInfoDer = await cms.sign(plaintext, privateKey, certificate);

      const signedData = deserializeSignedData(contentInfoDer);
      expect(signedData).toHaveProperty('certificates', []);
    });

    test('Certificates should optionally be attached', async () => {
      const certificate2 = await generateStubCert();
      const contentInfoDer = await cms.sign(
        plaintext,
        privateKey,
        certificate,
        new Set([certificate, certificate2]),
      );

      const signedData = deserializeSignedData(contentInfoDer);
      expect(signedData).toHaveProperty('certificates');
      expect(signedData.certificates).toHaveLength(2);
      expectPkijsValuesToBeEqual(
        // @ts-ignore
        signedData.certificates[0],
        certificate.pkijsCertificate,
      );
      expectPkijsValuesToBeEqual(
        // @ts-ignore
        signedData.certificates[1],
        certificate2.pkijsCertificate,
      );
    });
  });

  describe('Hashing', () => {
    test('SHA-256 should be used by default', async () => {
      const contentInfoDer = await cms.sign(plaintext, privateKey, certificate);

      const digestAttribute = deserializeSignerInfoAttribute(contentInfoDer, oids.CMS_ATTR_DIGEST);
      expect(
        // @ts-ignore
        Buffer.from(digestAttribute.values[0].valueBlock.valueHex).toString('hex'),
      ).toEqual(sha256Hex(plaintext));
    });

    test.each([['SHA-384', 'SHA-512']])('%s should be supported', async hashingAlgorithmName => {
      jest.spyOn(pkijs.SignedData.prototype, 'sign');
      const contentInfoDer = await cms.sign(plaintext, privateKey, certificate, new Set(), {
        hashingAlgorithmName,
      });

      // @ts-ignore
      const signCall = pkijs.SignedData.prototype.sign.mock.calls[0];
      expect(signCall[2]).toEqual(hashingAlgorithmName);

      const digestAttribute = deserializeSignerInfoAttribute(contentInfoDer, oids.CMS_ATTR_DIGEST);
      expect(
        // @ts-ignore
        Buffer.from(digestAttribute.values[0].valueBlock.valueHex).toString('hex'),
      ).toEqual(
        createHash(hashingAlgorithmName.toLowerCase().replace('-', ''))
          .update(Buffer.from(plaintext))
          .digest('hex'),
      );
    });

    test('SHA-1 should not be a valid hashing function', async () => {
      expect.hasAssertions();

      try {
        await cms.sign(plaintext, privateKey, certificate, new Set(), {
          hashingAlgorithmName: 'SHA-1',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(CMSError);
        expect(error.message).toEqual('SHA-1 is disallowed by RS-018');
      }
    });
  });
});

describe('verifySignature', () => {
  test('A non-DER-encoded value should be refused', async () => {
    const invalidSignature = bufferToArray(Buffer.from('nope.jpeg'));
    await expectPromiseToReject(
      cms.verifySignature(invalidSignature, plaintext),
      new Error('Value is not DER-encoded'),
    );
  });

  test('Well-formed but invalid signatures should be rejected', async () => {
    const differentPlaintext = bufferToArray(Buffer.from('Different'));
    const signatureDer = await cms.sign(
      differentPlaintext,
      privateKey,
      certificate,
      new Set([certificate]),
    );
    await expectPromiseToReject(
      cms.verifySignature(signatureDer, plaintext),
      new CMSError('Invalid signature:  (PKI.js code: 14)'),
    );
  });

  test('Valid signatures should be accepted', async () => {
    const signatureDer = await cms.sign(plaintext, privateKey, certificate, new Set([certificate]));
    await cms.verifySignature(signatureDer, plaintext);
  });

  test('Signer certificate should be taken from attached certs if not passed', async () => {
    const signatureDer = await cms.sign(plaintext, privateKey, certificate, new Set([certificate]));
    await expect(cms.verifySignature(signatureDer, plaintext)).resolves.toEqual(expect.anything());
  });

  describe('Attached certificates', () => {
    test('Attached certificates field should be optional', async () => {
      const signatureWithCerts = await cms.sign(plaintext, privateKey, certificate);

      const signedData = deserializeSignedData(signatureWithCerts);
      // tslint:disable-next-line:no-delete no-object-mutation
      delete signedData.certificates;
      const contentInfo = new pkijs.ContentInfo({
        content: signedData.toSchema(true),
        contentType: oids.CMS_SIGNED_DATA,
      });
      const signatureWithoutCerts = contentInfo.toSchema().toBER(false);

      await cms.verifySignature(signatureWithoutCerts, plaintext, certificate);
    });

    test('Signer certificate should be passed explicitly if detached', async () => {
      const signatureDer = await cms.sign(plaintext, privateKey, certificate);
      await expect(cms.verifySignature(signatureDer, plaintext, certificate)).toResolve();
    });

    test('Valid embedded certificates should be trusted by default', async () => {
      const signatureDer = await cms.sign(
        plaintext,
        privateKey,
        certificate,
        new Set([certificate]),
      );
      await expect(cms.verifySignature(signatureDer, plaintext)).toResolve();
    });
  });

  test('Signature should be verified against any set of trusted certificates', async () => {
    const caKeyPair = await generateRSAKeyPair();
    const caCertificate = await generateStubCert({
      attributes: { isCA: true, serialNumber: 1 },
      subjectPublicKey: caKeyPair.publicKey,
    });
    const signerKeyPair = await generateRSAKeyPair();
    const signerCertificate = await generateStubCert({
      attributes: { serialNumber: 2 },
      issuerCertificate: caCertificate,
      issuerPrivateKey: caKeyPair.privateKey,
      subjectPublicKey: signerKeyPair.publicKey,
    });
    const signatureDer = await cms.sign(
      plaintext,
      signerKeyPair.privateKey,
      signerCertificate,
      new Set([caCertificate, signerCertificate]), // Trusted certificate is attached
    );

    await cms.verifySignature(signatureDer, plaintext, [reSerializeCertificate(caCertificate)]);
  });

  test('CA certificates should not have to be attached to SignedData', async () => {
    const caKeyPair = await generateRSAKeyPair();
    const caCertificate = await generateStubCert({
      attributes: { isCA: true, serialNumber: 1 },
      subjectPublicKey: caKeyPair.publicKey,
    });
    const signerKeyPair = await generateRSAKeyPair();
    const signerCertificate = await generateStubCert({
      attributes: { serialNumber: 2 },
      issuerCertificate: caCertificate,
      issuerPrivateKey: caKeyPair.privateKey,
      subjectPublicKey: signerKeyPair.publicKey,
    });
    const signatureDer = await cms.sign(
      plaintext,
      signerKeyPair.privateKey,
      signerCertificate,
      new Set([signerCertificate]), // Trusted certificate is detached
    );

    await cms.verifySignature(signatureDer, plaintext, [reSerializeCertificate(caCertificate)]);
  });

  test('Signature should fail if not done with a trusted certificate', async () => {
    const caKeyPair = await generateRSAKeyPair();
    const caCertificate = await generateStubCert({
      attributes: { isCA: true, serialNumber: 2 },
      subjectPublicKey: caKeyPair.publicKey,
    });
    const signatureDer = await cms.sign(plaintext, privateKey, certificate, new Set([certificate]));

    await expectPromiseToReject(
      cms.verifySignature(signatureDer, plaintext, [reSerializeCertificate(caCertificate)]),
      new CMSError(
        'Invalid signature: ' +
          "Validation of signer's certificate failed: No valid certificate paths found " +
          '(PKI.js code: 5)',
      ),
    );
  });

  test('Sender certificate should be returned if verification passes', async () => {
    const superfluousCertificate = await generateStubCert({
      attributes: { serialNumber: 2 },
      subjectPublicKey: (await generateRSAKeyPair()).publicKey,
    });
    const signatureDer = await cms.sign(
      plaintext,
      privateKey,
      certificate,
      new Set([superfluousCertificate, certificate]),
    );

    const { signerCertificate } = await cms.verifySignature(signatureDer, plaintext);

    expectPkijsValuesToBeEqual(signerCertificate.pkijsCertificate, certificate.pkijsCertificate);
  });

  describe('Signer certificate chain', () => {
    test('Chain should only contain the signer cert if no trusted certs are passed', async () => {
      const signatureDer = await cms.sign(
        plaintext,
        privateKey,
        certificate,
        new Set([certificate]),
      );

      const { signerCertificateChain } = await cms.verifySignature(signatureDer, plaintext);

      expect(signerCertificateChain).toHaveLength(1);
      expectPkijsValuesToBeEqual(
        signerCertificateChain[0].pkijsCertificate,
        certificate.pkijsCertificate,
      );
    });

    test('Chain should be populated when trusted certs are passed', async () => {
      const rootCaKeyPair = await generateRSAKeyPair();
      const rootCaCertificate = await generateStubCert({
        attributes: { isCA: true, serialNumber: 1 },
        subjectPublicKey: rootCaKeyPair.publicKey,
      });
      const caKeyPair = await generateRSAKeyPair();
      const caCertificate = await generateStubCert({
        attributes: { isCA: true, serialNumber: 2 },
        issuerCertificate: rootCaCertificate,
        issuerPrivateKey: rootCaKeyPair.privateKey,
        subjectPublicKey: caKeyPair.publicKey,
      });
      const signerKeyPair = await generateRSAKeyPair();
      const signerCertificate = await generateStubCert({
        attributes: { serialNumber: 3 },
        issuerCertificate: caCertificate,
        issuerPrivateKey: caKeyPair.privateKey,
        subjectPublicKey: signerKeyPair.publicKey,
      });
      const signatureDer = await cms.sign(
        plaintext,
        signerKeyPair.privateKey,
        signerCertificate,
        new Set([signerCertificate]),
      );

      const { signerCertificateChain } = await cms.verifySignature(signatureDer, plaintext, [
        reSerializeCertificate(rootCaCertificate),
        reSerializeCertificate(caCertificate),
      ]);

      expect(signerCertificateChain).toHaveLength(3);
      expectPkijsValuesToBeEqual(
        signerCertificateChain[2].pkijsCertificate,
        rootCaCertificate.pkijsCertificate,
      );
      expectPkijsValuesToBeEqual(
        signerCertificateChain[1].pkijsCertificate,
        caCertificate.pkijsCertificate,
      );
      expectPkijsValuesToBeEqual(
        signerCertificateChain[0].pkijsCertificate,
        signerCertificate.pkijsCertificate,
      );
    });
  });
});

function deserializeContentInfo(contentInfoDer: ArrayBuffer): pkijs.ContentInfo {
  return new pkijs.ContentInfo({ schema: deserializeDer(contentInfoDer) });
}

function deserializeSignedData(signedDataDer: ArrayBuffer): pkijs.SignedData {
  const contentInfo = deserializeContentInfo(signedDataDer);
  return new pkijs.SignedData({ schema: contentInfo.content });
}

function deserializeSignerInfo(contentInfoDer: ArrayBuffer): pkijs.SignerInfo {
  const pkijsSignedData = deserializeSignedData(contentInfoDer);
  return pkijsSignedData.signerInfos[0];
}

function deserializeSignerInfoAttribute(
  contentInfoDer: ArrayBuffer,
  attributeOid: string,
): pkijs.Attribute {
  const signerInfo = deserializeSignerInfo(contentInfoDer);
  const attributes = (signerInfo.signedAttrs as pkijs.SignedAndUnsignedAttributes).attributes;
  const matchingAttrs = attributes.filter(a => a.type === attributeOid);
  expect(matchingAttrs).toHaveLength(1);
  return matchingAttrs[0];
}

function deserializeEnvelopedData(contentInfoDer: ArrayBuffer): pkijs.EnvelopedData {
  const contentInfo = deserializeContentInfo(contentInfoDer);
  return new pkijs.EnvelopedData({ schema: contentInfo.content });
}

function reSerializeCertificate(cert: Certificate): Certificate {
  // TODO: Raise bug in PKI.js project
  // PKI.js Certificate instances may not always have all the necessary fields when initialized,
  // which will lead to unhandled exceptions. They'll have the right fields when they're
  // deserialized, though.
  return Certificate.deserialize(cert.serialize());
}
