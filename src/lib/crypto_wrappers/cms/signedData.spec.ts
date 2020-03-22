// tslint:disable:no-let no-object-mutation
import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import { createHash } from 'crypto';
import * as pkijs from 'pkijs';

import {
  expectAsn1ValuesToBeEqual,
  expectBuffersToEqual,
  expectPkijsValuesToBeEqual,
  expectPromiseToReject,
  generateStubCert,
  sha256Hex,
} from '../../_test_utils';
import * as oids from '../../oids';
import { generateRSAKeyPair } from '../keys';
import Certificate from '../x509/Certificate';
import { deserializeContentInfo, serializeContentInfo } from './_test_utils';
import CMSError from './CMSError';
import { sign, verifySignature } from './signedData';

const plaintext = bufferToArray(Buffer.from('Winter is coming'));

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

describe('sign', () => {
  test('SignedData value should be wrapped in ContentInfo', async () => {
    const contentInfoDer = await sign(plaintext, privateKey, certificate);

    const contentInfo = deserializeContentInfo(contentInfoDer);
    expect(contentInfo.contentType).toEqual(oids.CMS_SIGNED_DATA);
    expect(contentInfo.content).toBeInstanceOf(asn1js.Sequence);
  });

  test('SignedData version should be 1', async () => {
    const contentInfoDer = await sign(plaintext, privateKey, certificate);

    const pkijsSignedData = deserializeSignedData(contentInfoDer);
    expect(pkijsSignedData).toHaveProperty('version', 1);
  });

  describe('SignerInfo', () => {
    test('There should only be one SignerInfo', async () => {
      const contentInfoDer = await sign(plaintext, privateKey, certificate);

      const pkijsSignedData = deserializeSignedData(contentInfoDer);
      expect(pkijsSignedData.signerInfos).toHaveLength(1);
      expect(pkijsSignedData.signerInfos[0]).toBeInstanceOf(pkijs.SignerInfo);
    });

    test('Version should be 1', async () => {
      const contentInfoDer = await sign(plaintext, privateKey, certificate);

      const signerInfo = deserializeSignerInfo(contentInfoDer);
      expect(signerInfo).toHaveProperty('version', 1);
    });

    test('SignerIdentifier should be IssuerAndSerialNumber', async () => {
      const contentInfoDer = await sign(plaintext, privateKey, certificate);

      const signerInfo = deserializeSignerInfo(contentInfoDer);
      expect(signerInfo.sid).toBeInstanceOf(pkijs.IssuerAndSerialNumber);
      expectPkijsValuesToBeEqual(signerInfo.sid.issuer, certificate.pkijsCertificate.issuer);
      expectAsn1ValuesToBeEqual(
        signerInfo.sid.serialNumber,
        certificate.pkijsCertificate.serialNumber,
      );
    });

    describe('SignedAttributes', () => {
      test('Signed attributes should be present', async () => {
        const contentInfoDer = await sign(plaintext, privateKey, certificate);

        const signerInfo = deserializeSignerInfo(contentInfoDer);
        expect(signerInfo.signedAttrs).toBeInstanceOf(pkijs.SignedAndUnsignedAttributes);
        expect(signerInfo.signedAttrs).toHaveProperty('type', 0);
      });

      test('Content type attribute should be set to CMS Data', async () => {
        const contentInfoDer = await sign(plaintext, privateKey, certificate);

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
        const contentInfoDer = await sign(plaintext, privateKey, certificate);

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
    test('The signer certificate should be attached', async () => {
      const contentInfoDer = await sign(plaintext, privateKey, certificate);

      const signedData = deserializeSignedData(contentInfoDer);
      expect(signedData.certificates).toHaveLength(1);
      expectPkijsValuesToBeEqual(
        (signedData.certificates as readonly pkijs.Certificate[])[0],
        certificate.pkijsCertificate,
      );
    });

    test('CA certificate chain should optionally be attached', async () => {
      const rootCaCertificate = await generateStubCert();
      const intermediateCaCertificate = await generateStubCert();
      const contentInfoDer = await sign(plaintext, privateKey, certificate, [
        intermediateCaCertificate,
        rootCaCertificate,
      ]);

      const signedData = deserializeSignedData(contentInfoDer);
      expect(signedData).toHaveProperty('certificates');
      expect(signedData.certificates).toHaveLength(3);
      const attachedCertificates = signedData.certificates as readonly pkijs.Certificate[];
      expectPkijsValuesToBeEqual(attachedCertificates[0], certificate.pkijsCertificate);
      expectPkijsValuesToBeEqual(
        attachedCertificates[1],
        intermediateCaCertificate.pkijsCertificate,
      );
      expectPkijsValuesToBeEqual(attachedCertificates[2], rootCaCertificate.pkijsCertificate);
    });
  });

  describe('Hashing', () => {
    test('SHA-256 should be used by default', async () => {
      const contentInfoDer = await sign(plaintext, privateKey, certificate);

      const digestAttribute = deserializeSignerInfoAttribute(contentInfoDer, oids.CMS_ATTR_DIGEST);
      expect(
        // @ts-ignore
        Buffer.from(digestAttribute.values[0].valueBlock.valueHex).toString('hex'),
      ).toEqual(sha256Hex(plaintext));
    });

    test.each([['SHA-384', 'SHA-512']])('%s should be supported', async hashingAlgorithmName => {
      jest.spyOn(pkijs.SignedData.prototype, 'sign');
      const contentInfoDer = await sign(plaintext, privateKey, certificate, [], {
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
        await sign(plaintext, privateKey, certificate, [], { hashingAlgorithmName: 'SHA-1' });
      } catch (error) {
        expect(error).toBeInstanceOf(CMSError);
        expect(error.message).toEqual('SHA-1 is disallowed by RS-018');
      }
    });
  });

  test('Content should be attached', async () => {
    jest.spyOn(pkijs.SignedData.prototype, 'sign');
    const contentInfoDer = await sign(plaintext, privateKey, certificate);

    const signedData = deserializeSignedData(contentInfoDer);
    expect(signedData.encapContentInfo).toBeInstanceOf(pkijs.EncapsulatedContentInfo);
    expect(signedData.encapContentInfo).toHaveProperty('eContentType', oids.CMS_DATA);
    expect(signedData.encapContentInfo).toHaveProperty('eContent');
    const plaintextOctetString = signedData.encapContentInfo.eContent.valueBlock.value[0];
    expectBuffersToEqual(
      (plaintextOctetString as asn1js.OctetString).valueBlock.valueHex,
      plaintext,
    );
  });
});

describe('verifySignature', () => {
  test('A non-DER-encoded value should be refused', async () => {
    const invalidSignature = bufferToArray(Buffer.from('nope.jpeg'));
    await expectPromiseToReject(
      verifySignature(invalidSignature),
      new CMSError('Could not deserialize CMS ContentInfo: Value is not DER-encoded'),
    );
  });

  test('Well-formed but invalid signatures should be rejected', async () => {
    // Let's tamper with the payload
    const signatureDer = await sign(plaintext, privateKey, certificate);
    const differentPlaintext = bufferToArray(Buffer.from('Different'));
    const cmsSignedData = deserializeSignedData(signatureDer);
    // tslint:disable-next-line:no-object-mutation
    cmsSignedData.encapContentInfo = new pkijs.EncapsulatedContentInfo({
      eContent: new asn1js.OctetString({ valueHex: differentPlaintext }),
      eContentType: oids.CMS_DATA,
    });
    const invalidCmsSignedDataSerialized = serializeContentInfo(
      cmsSignedData.toSchema(true),
      oids.CMS_SIGNED_DATA,
    );

    await expectPromiseToReject(
      verifySignature(invalidCmsSignedDataSerialized),
      new CMSError('Invalid signature:  (PKI.js code: 14)'),
    );
  });

  test('Value should be refused if content is not encapsulated', async () => {
    const validSignedDataSerialized = await sign(plaintext, privateKey, certificate);
    const signedData = deserializeSignedData(validSignedDataSerialized);
    // tslint:disable-next-line:no-delete
    delete signedData.encapContentInfo.eContent;
    const invalidSignedData = new pkijs.ContentInfo({
      content: signedData.toSchema(true),
      contentType: oids.CMS_SIGNED_DATA,
    });
    const invalidSignedDataSerialized = invalidSignedData.toSchema().toBER(false);

    await expect(verifySignature(invalidSignedDataSerialized)).rejects.toMatchObject<
      Partial<CMSError>
    >({
      message: 'CMS SignedData value should encapsulate content',
    });
  });

  test('Valid signatures should be accepted', async () => {
    const signatureDer = await sign(plaintext, privateKey, certificate);
    await verifySignature(signatureDer);
  });

  test('Plaintext should be output when verification passes', async () => {
    const signatureDer = await sign(plaintext, privateKey, certificate);

    const signatureVerification = await verifySignature(signatureDer);

    expectBuffersToEqual(signatureVerification.plaintext, plaintext);
  });

  test('Large plaintexts chunked by PKI.js should be put back together', async () => {
    const largePlaintext = bufferToArray(Buffer.from('a'.repeat(2 ** 20)));
    const signatureDer = await sign(largePlaintext, privateKey, certificate);

    const signatureVerification = await verifySignature(signatureDer);

    expectBuffersToEqual(signatureVerification.plaintext, largePlaintext);
  });

  test('Signer certificate should be output when verification passes', async () => {
    const signatureDer = await sign(plaintext, privateKey, certificate);

    const { signerCertificate } = await verifySignature(signatureDer);

    expectPkijsValuesToBeEqual(signerCertificate.pkijsCertificate, certificate.pkijsCertificate);
  });

  test('Attached CA certificates should be output when verification passes', async () => {
    const rootCaKeyPair = await generateRSAKeyPair();
    const rootCaCertificate = await generateStubCert({
      attributes: { isCA: true },
      subjectPublicKey: rootCaKeyPair.publicKey,
    });
    const intermediateCaKeyPair = await generateRSAKeyPair();
    const intermediateCaCertificate = await generateStubCert({
      attributes: { isCA: true },
      issuerCertificate: rootCaCertificate,
      issuerPrivateKey: rootCaKeyPair.privateKey,
      subjectPublicKey: intermediateCaKeyPair.publicKey,
    });
    const signerKeyPair = await generateRSAKeyPair();
    const signerCertificate = await generateStubCert({
      issuerCertificate: intermediateCaCertificate,
      issuerPrivateKey: intermediateCaKeyPair.privateKey,
      subjectPublicKey: signerKeyPair.publicKey,
    });
    const signatureDer = await sign(plaintext, signerKeyPair.privateKey, signerCertificate, [
      intermediateCaCertificate,
      rootCaCertificate,
    ]);

    const { attachedCertificates } = await verifySignature(signatureDer);

    expect(attachedCertificates).toHaveLength(3);
    expectPkijsValuesToBeEqual(
      attachedCertificates[2].pkijsCertificate,
      rootCaCertificate.pkijsCertificate,
    );
    expectPkijsValuesToBeEqual(
      attachedCertificates[1].pkijsCertificate,
      intermediateCaCertificate.pkijsCertificate,
    );
    expectPkijsValuesToBeEqual(
      attachedCertificates[0].pkijsCertificate,
      signerCertificate.pkijsCertificate,
    );
  });
});

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
