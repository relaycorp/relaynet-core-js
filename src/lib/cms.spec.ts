import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import {
  asn1DerDecode,
  expectAsn1ValuesToBeEqual,
  expectPkijsValuesToBeEqual,
  generateStubCert
} from './_test_utils';
import * as cms from './cms';
import { generateRsaKeys } from './crypto';
import * as oids from './oids';
import Certificate from './pki/Certificate';

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
    const contentInfoDer = await cms.sign(certificate);

    const contentInfo = deserializeContentInfo(contentInfoDer);
    expect(contentInfo.contentType).toEqual(oids.CMS_SIGNED_DATA);
    expect(contentInfo.content).toBeInstanceOf(asn1js.Sequence);
  });

  describe('SignedData', () => {
    test('Version should be 1', async () => {
      const contentInfoDer = await cms.sign(certificate);

      const pkijsSignedData = deserializePkijsSignedData(contentInfoDer);
      expect(pkijsSignedData).toHaveProperty('version', 1);
    });

    describe('SignerInfo', () => {
      test('There should only be one SignerInfo', async () => {
        const contentInfoDer = await cms.sign(certificate);

        const pkijsSignedData = deserializePkijsSignedData(contentInfoDer);
        expect(pkijsSignedData.signerInfos).toHaveLength(1);
        expect(pkijsSignedData.signerInfos[0]).toBeInstanceOf(pkijs.SignerInfo);
      });

      test('Version should be 1', async () => {
        const contentInfoDer = await cms.sign(certificate);

        const signerInfo = deserializeSignerInfo(contentInfoDer);
        expect(signerInfo).toHaveProperty('version', 1);
      });

      test('SignerIdentifier should be IssuerAndSerialNumber', async () => {
        const contentInfoDer = await cms.sign(certificate);

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
