import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import { createHash } from 'crypto';
import * as pkijs from 'pkijs';
import {
  asn1DerDecode,
  expectAsn1ValuesToBeEqual,
  expectPkijsValuesToBeEqual,
  generateStubCert,
  sha256Hex
} from './_test_utils';
import * as cms from './cms';
import CMSError from './CMSError';
import { generateRsaKeys } from './crypto';
import * as oids from './oids';
import Certificate from './pki/Certificate';

const plaintext = bufferToArray(Buffer.from('Winter is coming'));

describe('sign', () => {
  // tslint:disable-next-line:no-let
  let privateKey: CryptoKey;
  // tslint:disable-next-line:no-let
  let certificate: Certificate;
  beforeAll(async () => {
    const keyPair = await generateRsaKeys();
    privateKey = keyPair.privateKey;
    certificate = await generateStubCert({
      issuerPrivateKey: privateKey,
      subjectPublicKey: keyPair.publicKey
    });
  });

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
      expectPkijsValuesToBeEqual(
        signerInfo.sid.issuer,
        certificate.pkijsCertificate.issuer
      );
      expectAsn1ValuesToBeEqual(
        signerInfo.sid.serialNumber,
        certificate.pkijsCertificate.serialNumber
      );
    });

    test('Signature should be detached', async () => {
      jest.spyOn(pkijs.SignedData.prototype, 'sign');
      const contentInfoDer = await cms.sign(plaintext, privateKey, certificate);

      const signedData = deserializeSignedData(contentInfoDer);
      expect(signedData.encapContentInfo).toBeInstanceOf(
        pkijs.EncapsulatedContentInfo
      );
      expect(signedData.encapContentInfo).toHaveProperty(
        'eContentType',
        oids.CMS_DATA
      );
      expect(signedData.encapContentInfo).not.toHaveProperty('eContent');
    });

    describe('SignedAttributes', () => {
      test('Signed attributes should be present', async () => {
        const contentInfoDer = await cms.sign(
          plaintext,
          privateKey,
          certificate
        );

        const signerInfo = deserializeSignerInfo(contentInfoDer);
        expect(signerInfo.signedAttrs).toBeInstanceOf(
          pkijs.SignedAndUnsignedAttributes
        );
        expect(signerInfo.signedAttrs).toHaveProperty('type', 0);
      });

      test('Content type attribute should be set to CMS Data', async () => {
        const contentInfoDer = await cms.sign(
          plaintext,
          privateKey,
          certificate
        );

        const contentTypeAttribute = deserializeSignerInfoAttribute(
          contentInfoDer,
          oids.CMS_ATTR_CONTENT_TYPE
        );
        // @ts-ignore
        expect(contentTypeAttribute.values).toHaveLength(1);
        expect(
          // @ts-ignore
          contentTypeAttribute.values[0].valueBlock.toString()
        ).toEqual(oids.CMS_DATA);
      });

      test('Plaintext digest should be present', async () => {
        const contentInfoDer = await cms.sign(
          plaintext,
          privateKey,
          certificate
        );

        const digestAttribute = deserializeSignerInfoAttribute(
          contentInfoDer,
          oids.CMS_ATTR_DIGEST
        );
        // @ts-ignore
        expect(digestAttribute.values).toHaveLength(1);
        expect(
          // @ts-ignore
          digestAttribute.values[0].valueBlock.valueHex
        ).toBeTruthy();
      });
    });
  });

  describe('Embedded certificates', () => {
    test('The signer certificate should not be embedded', async () => {
      const contentInfoDer = await cms.sign(plaintext, privateKey, certificate);

      const signedData = deserializeSignedData(contentInfoDer);
      expect(signedData).toHaveProperty('certificates', []);
    });

    test('Certificates should optionally be embedded', async () => {
      const certificate2 = await generateStubCert();
      const contentInfoDer = await cms.sign(
        plaintext,
        privateKey,
        certificate,
        [certificate, certificate2]
      );

      const signedData = deserializeSignedData(contentInfoDer);
      expect(signedData).toHaveProperty('certificates');
      expect(signedData.certificates).toHaveLength(2);
      expectPkijsValuesToBeEqual(
        // @ts-ignore
        signedData.certificates[0],
        certificate.pkijsCertificate
      );
      expectPkijsValuesToBeEqual(
        // @ts-ignore
        signedData.certificates[1],
        certificate2.pkijsCertificate
      );
    });
  });

  describe('Hashing', () => {
    test('SHA-256 should be used by default', async () => {
      const contentInfoDer = await cms.sign(plaintext, privateKey, certificate);

      const digestAttribute = deserializeSignerInfoAttribute(
        contentInfoDer,
        oids.CMS_ATTR_DIGEST
      );
      expect(
        // @ts-ignore
        Buffer.from(digestAttribute.values[0].valueBlock.valueHex).toString(
          'hex'
        )
      ).toEqual(sha256Hex(plaintext));
    });

    test.each([['SHA-384', 'SHA-512']])(
      '%s should be supported',
      async hashingAlgorithmName => {
        jest.spyOn(pkijs.SignedData.prototype, 'sign');
        const contentInfoDer = await cms.sign(
          plaintext,
          privateKey,
          certificate,
          [],
          hashingAlgorithmName
        );

        // @ts-ignore
        const signCall = pkijs.SignedData.prototype.sign.mock.calls[0];
        expect(signCall[2]).toEqual(hashingAlgorithmName);

        const digestAttribute = deserializeSignerInfoAttribute(
          contentInfoDer,
          oids.CMS_ATTR_DIGEST
        );
        expect(
          // @ts-ignore
          Buffer.from(digestAttribute.values[0].valueBlock.valueHex).toString(
            'hex'
          )
        ).toEqual(
          createHash(hashingAlgorithmName.toLowerCase().replace('-', ''))
            .update(Buffer.from(plaintext))
            .digest('hex')
        );
      }
    );

    test('SHA-1 should not be a valid hashing function', async () => {
      expect.hasAssertions();

      try {
        await cms.sign(plaintext, privateKey, certificate, [], 'SHA-1');
      } catch (error) {
        expect(error).toBeInstanceOf(CMSError);
        expect(error.message).toEqual('SHA-1 is disallowed by RS-018');
      }
    });
  });
});

function deserializeContentInfo(
  contentInfoDer: ArrayBuffer
): pkijs.ContentInfo {
  return new pkijs.ContentInfo({ schema: asn1DerDecode(contentInfoDer) });
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
  attributeOid: string
): pkijs.Attribute {
  const signerInfo = deserializeSignerInfo(contentInfoDer);
  const attributes = (signerInfo.signedAttrs as pkijs.SignedAndUnsignedAttributes)
    .attributes;
  const matchingAttrs = attributes.filter(a => a.type === attributeOid);
  expect(matchingAttrs).toHaveLength(1);
  return matchingAttrs[0];
}
