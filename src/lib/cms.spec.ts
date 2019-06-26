import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import * as pkijs from 'pkijs';
import {
  asn1DerDecode,
  expectAsn1ValuesToBeEqual,
  expectPkijsValuesToBeEqual,
  generateStubCert,
  sha256Hex
} from './_test_utils';
import * as cms from './cms';
import { generateRsaKeys } from './crypto';
import * as oids from './oids';
import Certificate from './pki/Certificate';

describe('sign', () => {
  const plainText = bufferToArray(Buffer.from('Winter is coming'));

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
    const contentInfoDer = await cms.sign(plainText, certificate);

    const contentInfo = deserializeContentInfo(contentInfoDer);
    expect(contentInfo.contentType).toEqual(oids.CMS_SIGNED_DATA);
    expect(contentInfo.content).toBeInstanceOf(asn1js.Sequence);
  });

  describe('SignedData', () => {
    test('Version should be 1', async () => {
      const contentInfoDer = await cms.sign(plainText, certificate);

      const pkijsSignedData = deserializePkijsSignedData(contentInfoDer);
      expect(pkijsSignedData).toHaveProperty('version', 1);
    });

    describe('SignerInfo', () => {
      test('There should only be one SignerInfo', async () => {
        const contentInfoDer = await cms.sign(plainText, certificate);

        const pkijsSignedData = deserializePkijsSignedData(contentInfoDer);
        expect(pkijsSignedData.signerInfos).toHaveLength(1);
        expect(pkijsSignedData.signerInfos[0]).toBeInstanceOf(pkijs.SignerInfo);
      });

      test('Version should be 1', async () => {
        const contentInfoDer = await cms.sign(plainText, certificate);

        const signerInfo = deserializeSignerInfo(contentInfoDer);
        expect(signerInfo).toHaveProperty('version', 1);
      });

      test('SignerIdentifier should be IssuerAndSerialNumber', async () => {
        const contentInfoDer = await cms.sign(plainText, certificate);

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

      function deserializeSignerInfo(
        contentInfoDer: ArrayBuffer
      ): pkijs.SignerInfo {
        const pkijsSignedData = deserializePkijsSignedData(contentInfoDer);
        return pkijsSignedData.signerInfos[0];
      }

      describe('SignedAttributes', () => {
        test('Signed attributes should be present', async () => {
          const contentInfoDer = await cms.sign(plainText, certificate);

          const signerInfo = deserializeSignerInfo(contentInfoDer);
          expect(signerInfo.signedAttrs).toBeInstanceOf(
            pkijs.SignedAndUnsignedAttributes
          );
          expect(signerInfo.signedAttrs).toHaveProperty('type', 0);
        });

        test('Content type attribute should be set to CMS Data', async () => {
          const contentInfoDer = await cms.sign(plainText, certificate);

          const signerInfo = deserializeSignerInfo(contentInfoDer);
          const matchingAttrs = (signerInfo.signedAttrs as pkijs.SignedAndUnsignedAttributes).attributes.filter(
            a => a.type === oids.CMS_ATTR_CONTENT_TYPE
          );
          const contentTypeAttribute = matchingAttrs[0];
          // @ts-ignore
          expect(contentTypeAttribute.values).toHaveLength(1);
          expect(
            // @ts-ignore
            contentTypeAttribute.values[0].valueBlock.toString()
          ).toEqual(oids.CMS_DATA);
        });

        test('Plaintext digest should be calculated and stored', async () => {
          const contentInfoDer = await cms.sign(plainText, certificate);

          const signerInfo = deserializeSignerInfo(contentInfoDer);
          const matchingAttrs = (signerInfo.signedAttrs as pkijs.SignedAndUnsignedAttributes).attributes.filter(
            a => a.type === oids.CMS_ATTR_DIGEST
          );
          const digestAttribute = matchingAttrs[0];
          // @ts-ignore
          expect(digestAttribute.values).toHaveLength(1);
          expect(
            // @ts-ignore
            Buffer.from(digestAttribute.values[0].valueBlock.valueHex).toString(
              'hex'
            )
          ).toEqual(sha256Hex(plainText));
        });

        test.todo('Hashing function should be customizable');

        test.todo('SHA-1 should not be a valid hashing function');
      });
    });
  });

  function deserializeContentInfo(
    contentInfoDer: ArrayBuffer
  ): pkijs.ContentInfo {
    return new pkijs.ContentInfo({
      schema: asn1DerDecode(contentInfoDer)
    });
  }

  function deserializePkijsSignedData(
    signedDataDer: ArrayBuffer
  ): pkijs.SignedData {
    const contentInfo = deserializeContentInfo(signedDataDer);
    return new pkijs.SignedData({ schema: contentInfo.content });
  }
});
