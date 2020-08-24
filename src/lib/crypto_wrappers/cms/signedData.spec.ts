// tslint:disable:no-let no-object-mutation
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

import {
  arrayBufferFrom,
  calculateDigestHex,
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
import { sign, SignedData, verifySignature } from './signedData';

const plaintext = arrayBufferFrom('Winter is coming');

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
  test('SignedData version should be 1', async () => {
    const signedData = await SignedData.sign(plaintext, privateKey, certificate);

    expect(signedData.pkijsSignedData).toHaveProperty('version', 1);
  });

  describe('SignerInfo', () => {
    test('There should only be one SignerInfo', async () => {
      const signedData = await SignedData.sign(plaintext, privateKey, certificate);

      expect(signedData.pkijsSignedData.signerInfos).toHaveLength(1);
      expect(signedData.pkijsSignedData.signerInfos[0]).toBeInstanceOf(pkijs.SignerInfo);
    });

    test('Version should be 1', async () => {
      const signedData = await SignedData.sign(plaintext, privateKey, certificate);

      expect(signedData.pkijsSignedData.signerInfos[0]).toHaveProperty('version', 1);
    });

    test('SignerIdentifier should be IssuerAndSerialNumber', async () => {
      const signedData = await SignedData.sign(plaintext, privateKey, certificate);

      const signerInfo = signedData.pkijsSignedData.signerInfos[0];
      expect(signerInfo.sid).toBeInstanceOf(pkijs.IssuerAndSerialNumber);
      expectPkijsValuesToBeEqual(signerInfo.sid.issuer, certificate.pkijsCertificate.issuer);
      expectAsn1ValuesToBeEqual(
        signerInfo.sid.serialNumber,
        certificate.pkijsCertificate.serialNumber,
      );
    });

    describe('SignedAttributes', () => {
      test('Signed attributes should be present', async () => {
        const signedData = await SignedData.sign(plaintext, privateKey, certificate);

        const signerInfo = signedData.pkijsSignedData.signerInfos[0];
        expect(signerInfo.signedAttrs).toBeInstanceOf(pkijs.SignedAndUnsignedAttributes);
        expect(signerInfo.signedAttrs).toHaveProperty('type', 0);
      });

      test('Content type attribute should be set to CMS Data', async () => {
        const signedData = await SignedData.sign(plaintext, privateKey, certificate);

        const contentTypeAttribute = getSignerInfoAttribute(
          signedData.pkijsSignedData.signerInfos[0],
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
        const signedData = await SignedData.sign(plaintext, privateKey, certificate);

        const digestAttribute = getSignerInfoAttribute(
          signedData.pkijsSignedData.signerInfos[0],
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
      const signedData = await SignedData.sign(plaintext, privateKey, certificate);

      expect(signedData.pkijsSignedData.certificates).toHaveLength(1);
      expectPkijsValuesToBeEqual(
        (signedData.pkijsSignedData.certificates as readonly pkijs.Certificate[])[0],
        certificate.pkijsCertificate,
      );
    });

    test('CA certificate chain should optionally be attached', async () => {
      const rootCaCertificate = await generateStubCert();
      const intermediateCaCertificate = await generateStubCert();
      const signedData = await SignedData.sign(plaintext, privateKey, certificate, [
        intermediateCaCertificate,
        rootCaCertificate,
      ]);

      expect(signedData.pkijsSignedData.certificates).toHaveLength(3);
      const attachedCertificates = signedData.pkijsSignedData
        .certificates as readonly pkijs.Certificate[];
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
      const signedData = await SignedData.sign(plaintext, privateKey, certificate);

      const digestAttribute = getSignerInfoAttribute(
        signedData.pkijsSignedData.signerInfos[0],
        oids.CMS_ATTR_DIGEST,
      );
      expect(
        // @ts-ignore
        Buffer.from(digestAttribute.values[0].valueBlock.valueHex).toString('hex'),
      ).toEqual(sha256Hex(plaintext));
    });

    test.each([['SHA-384', 'SHA-512']])('%s should be supported', async (hashingAlgorithmName) => {
      const signedData = await SignedData.sign(plaintext, privateKey, certificate, [], {
        hashingAlgorithmName,
      });

      const digestAttribute = getSignerInfoAttribute(
        signedData.pkijsSignedData.signerInfos[0],
        oids.CMS_ATTR_DIGEST,
      );
      const algorithmNameNodejs = hashingAlgorithmName.toLowerCase().replace('-', '');
      expect(
        // @ts-ignore
        Buffer.from(digestAttribute.values[0].valueBlock.valueHex).toString('hex'),
      ).toEqual(calculateDigestHex(algorithmNameNodejs, plaintext));
    });

    test('SHA-1 should not be a valid hashing function', async () => {
      expect.hasAssertions();

      try {
        await SignedData.sign(plaintext, privateKey, certificate, [], {
          hashingAlgorithmName: 'SHA-1',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(CMSError);
        expect(error.message).toEqual('SHA-1 is disallowed by RS-018');
      }
    });
  });

  test('Content should be attached', async () => {
    jest.spyOn(pkijs.SignedData.prototype, 'sign');
    const signedData = await SignedData.sign(plaintext, privateKey, certificate);

    const encapContentInfo = signedData.pkijsSignedData.encapContentInfo;
    expect(encapContentInfo).toBeInstanceOf(pkijs.EncapsulatedContentInfo);
    expect(encapContentInfo).toHaveProperty('eContentType', oids.CMS_DATA);
    expect(encapContentInfo).toHaveProperty('eContent');
    const plaintextOctetString = encapContentInfo.eContent.valueBlock.value[0];
    expectBuffersToEqual(
      (plaintextOctetString as asn1js.OctetString).valueBlock.valueHex,
      plaintext,
    );
  });
});

describe('serialize', () => {
  test('SignedData value should be wrapped in ContentInfo', async () => {
    const signedData = await SignedData.sign(plaintext, privateKey, certificate);

    const signedDataSerialized = signedData.serialize();

    const contentInfo = deserializeContentInfo(signedDataSerialized);
    expect(contentInfo.content.toBER(false)).toEqual(
      signedData.pkijsSignedData.toSchema(true).toBER(false),
    );
  });

  test('ContentInfo OID should match that of SignedData values', async () => {
    const signedData = await SignedData.sign(plaintext, privateKey, certificate);

    const signedDataSerialized = signedData.serialize();

    const contentInfo = deserializeContentInfo(signedDataSerialized);
    expect(contentInfo.contentType).toEqual(oids.CMS_SIGNED_DATA);
  });
});

describe('verifySignature', () => {
  test('A non-DER-encoded value should be refused', async () => {
    const invalidSignature = arrayBufferFrom('nope.jpeg');
    await expectPromiseToReject(
      verifySignature(invalidSignature),
      new CMSError('Could not deserialize CMS ContentInfo: Value is not DER-encoded'),
    );
  });

  test('Well-formed but invalid signatures should be rejected', async () => {
    // Let's tamper with the payload
    const signatureDer = await sign(plaintext, privateKey, certificate);
    const differentPlaintext = arrayBufferFrom('Different');
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
    const largePlaintext = arrayBufferFrom('a'.repeat(2 ** 20));
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

function getSignerInfoAttribute(
  signerInfo: pkijs.SignerInfo,
  attributeOid: string,
): pkijs.Attribute {
  const attributes = (signerInfo.signedAttrs as pkijs.SignedAndUnsignedAttributes).attributes;
  const matchingAttrs = attributes.filter((a) => a.type === attributeOid);
  expect(matchingAttrs).toHaveLength(1);
  return matchingAttrs[0];
}
