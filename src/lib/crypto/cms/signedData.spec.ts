// tslint:disable:no-object-mutation

import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

import {
  arrayBufferFrom,
  calculateDigestHex,
  expectAsn1ValuesToBeEqual,
  expectArrayBuffersToEqual,
  expectPkijsValuesToBeEqual,
  generateStubCert,
  sha256Hex,
} from '../../_test_utils';
import { CMS_OIDS } from '../../oids';
import { HashingAlgorithm } from '../algorithms';
import { generateRSAKeyPair } from '../keys';
import { RsaPssPrivateKey } from '../PrivateKey';
import { MockRsaPssProvider } from '../webcrypto/_test_utils';
import { Certificate } from '../x509/Certificate';
import { deserializeContentInfo, serializeContentInfo } from './_test_utils';
import { CMSError } from './CMSError';
import { SignedData } from './signedData';

const plaintext = arrayBufferFrom('Winter is coming');

let keyPair: CryptoKeyPair;
let certificate: Certificate;
beforeAll(async () => {
  keyPair = await generateRSAKeyPair();
  certificate = await generateStubCert({
    issuerPrivateKey: keyPair.privateKey,
    subjectPublicKey: keyPair.publicKey,
  });
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('sign', () => {
  test('SignedData version should be 1', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

    expect(signedData.pkijsSignedData).toHaveProperty('version', 1);
  });

  test('Crypto in private key should be used if set', async () => {
    const provider = new MockRsaPssProvider();
    const privateKey = new RsaPssPrivateKey('SHA-256', provider);

    await expect(SignedData.sign(plaintext, privateKey, certificate)).toResolve();

    expect(provider.onSign).toBeCalled();
  });

  describe('SignerInfo', () => {
    test('There should only be one SignerInfo', async () => {
      const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

      expect(signedData.pkijsSignedData.signerInfos).toHaveLength(1);
      expect(signedData.pkijsSignedData.signerInfos[0]).toBeInstanceOf(pkijs.SignerInfo);
    });

    test('Version should be 1', async () => {
      const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

      expect(signedData.pkijsSignedData.signerInfos[0]).toHaveProperty('version', 1);
    });

    test('SignerIdentifier should be IssuerAndSerialNumber', async () => {
      const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

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
        const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

        const signerInfo = signedData.pkijsSignedData.signerInfos[0];
        expect(signerInfo.signedAttrs).toBeInstanceOf(pkijs.SignedAndUnsignedAttributes);
        expect(signerInfo.signedAttrs).toHaveProperty('type', 0);
      });

      test('Content type attribute should be set to CMS Data', async () => {
        const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

        const contentTypeAttribute = getSignerInfoAttribute(
          signedData.pkijsSignedData.signerInfos[0],
          CMS_OIDS.ATTR_CONTENT_TYPE,
        );
        // @ts-ignore
        expect(contentTypeAttribute.values).toHaveLength(1);
        expect(
          // @ts-ignore
          contentTypeAttribute.values[0].valueBlock.toString(),
        ).toEqual(CMS_OIDS.DATA);
      });

      test('Plaintext digest should be present', async () => {
        const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

        const digestAttribute = getSignerInfoAttribute(
          signedData.pkijsSignedData.signerInfos[0],
          CMS_OIDS.ATTR_DIGEST,
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
      const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

      expect(signedData.pkijsSignedData.certificates).toHaveLength(1);
      expectPkijsValuesToBeEqual(
        (signedData.pkijsSignedData.certificates as readonly pkijs.Certificate[])[0],
        certificate.pkijsCertificate,
      );
    });

    test('CA certificate chain should optionally be attached', async () => {
      const rootCaCertificate = await generateStubCert();
      const intermediateCaCertificate = await generateStubCert();
      const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate, [
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
      const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

      const digestAttribute = getSignerInfoAttribute(
        signedData.pkijsSignedData.signerInfos[0],
        CMS_OIDS.ATTR_DIGEST,
      );
      expect(
        // @ts-ignore
        Buffer.from(digestAttribute.values[0].valueBlock.valueHex).toString('hex'),
      ).toEqual(sha256Hex(plaintext));
    });

    test.each(['SHA-384', 'SHA-512'] as readonly HashingAlgorithm[])(
      '%s should be supported',
      async (hashingAlgorithmName) => {
        const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate, [], {
          hashingAlgorithmName,
        });

        const digestAttribute = getSignerInfoAttribute(
          signedData.pkijsSignedData.signerInfos[0],
          CMS_OIDS.ATTR_DIGEST,
        );
        const algorithmNameNodejs = hashingAlgorithmName.toLowerCase().replace('-', '');
        const digest = (digestAttribute as any).values[0].valueBlock.valueHex;
        expect(Buffer.from(digest).toString('hex')).toEqual(
          calculateDigestHex(algorithmNameNodejs, plaintext),
        );
      },
    );

    test('SHA-1 should not be a valid hashing function', async () => {
      expect.hasAssertions();

      try {
        await SignedData.sign(plaintext, keyPair.privateKey, certificate, [], {
          hashingAlgorithmName: 'SHA-1',
        } as any);
      } catch (error: any) {
        expect(error).toBeInstanceOf(CMSError);
        expect(error.message).toEqual('SHA-1 is disallowed by RS-018');
      }
    });
  });

  describe('Plaintext', () => {
    test('Plaintext should be encapsulated by default', async () => {
      const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

      const encapContentInfo = signedData.pkijsSignedData.encapContentInfo;
      expect(encapContentInfo).toBeInstanceOf(pkijs.EncapsulatedContentInfo);
      expect(encapContentInfo).toHaveProperty('eContentType', CMS_OIDS.DATA);
      expect(encapContentInfo).toHaveProperty('eContent');
      const plaintextOctetString = encapContentInfo.eContent!.valueBlock
        .value[0] as asn1js.OctetString;
      expectArrayBuffersToEqual(
        plaintextOctetString.valueBlock.valueHexView.slice().buffer,
        plaintext,
      );
    });

    test('Content should not be encapsulated if requested', async () => {
      const signedData = await SignedData.sign(
        plaintext,
        keyPair.privateKey,
        certificate,
        undefined,
        { encapsulatePlaintext: false },
      );

      const encapContentInfo = signedData.pkijsSignedData.encapContentInfo;
      expect(encapContentInfo).toBeInstanceOf(pkijs.EncapsulatedContentInfo);
      expect(encapContentInfo).toHaveProperty('eContentType', CMS_OIDS.DATA);
      expect(encapContentInfo).toHaveProperty('eContent', undefined);
    });
  });
});

describe('serialize', () => {
  test('SignedData value should be wrapped in ContentInfo', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

    const signedDataSerialized = signedData.serialize();

    const contentInfo = deserializeContentInfo(signedDataSerialized);
    expect(contentInfo.content.toBER(false)).toEqual(
      signedData.pkijsSignedData.toSchema(true).toBER(false),
    );
  });

  test('ContentInfo OID should match that of SignedData values', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

    const signedDataSerialized = signedData.serialize();

    const contentInfo = deserializeContentInfo(signedDataSerialized);
    expect(contentInfo.contentType).toEqual(CMS_OIDS.SIGNED_DATA);
  });
});

describe('deserialize', () => {
  test('A non-DER-encoded value should be refused', async () => {
    const invalidSignature = arrayBufferFrom('nope.jpeg');
    expect(() => SignedData.deserialize(invalidSignature)).toThrowWithMessage(
      CMSError,
      'Could not deserialize CMS ContentInfo: Value is not DER-encoded',
    );
  });

  test('ContentInfo wrapper should be required', async () => {
    const invalidSignature = new asn1js.Sequence().toBER(false);
    expect(() => SignedData.deserialize(invalidSignature)).toThrowWithMessage(
      CMSError,
      'Could not deserialize CMS ContentInfo: ' +
        "Object's schema was not verified against input data for ContentInfo",
    );
  });

  test('Malformed SignedData values should be refused', async () => {
    const invalidSignature = serializeContentInfo(new asn1js.Sequence(), '1.2.3.4');
    await expect(() => SignedData.deserialize(invalidSignature)).toThrowWithMessage(
      CMSError,
      'SignedData value is malformed',
    );
  });

  test('Well-formed SignedData values should be deserialized', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);
    const signedDataSerialized = signedData.serialize();

    const signedDataDeserialized = SignedData.deserialize(signedDataSerialized);

    expect(signedDataDeserialized.serialize()).toEqual(signedData.serialize());
  });
});

describe('verify', () => {
  test('Value should be refused if plaintext is not encapsulated or specified', async () => {
    const signedData = await SignedData.sign(
      plaintext,
      keyPair.privateKey,
      certificate,
      undefined,
      {
        encapsulatePlaintext: false,
      },
    );

    await expect(signedData.verify()).rejects.toMatchObject<Partial<CMSError>>({
      message: 'Plaintext should be encapsulated or explicitly set',
    });
  });

  test('Expected plaintext should be refused if one is already encapsulated', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

    await expect(signedData.verify(plaintext)).rejects.toEqual(
      new CMSError('No specific plaintext should be expected because one is already encapsulated'),
    );
  });

  test('Different detached plaintext should be rejected', async () => {
    const signedData = await SignedData.sign(
      plaintext,
      keyPair.privateKey,
      certificate,
      undefined,
      {
        encapsulatePlaintext: false,
      },
    );
    const differentPlaintext = arrayBufferFrom('this is an invalid plaintext');

    await expect(signedData.verify(differentPlaintext)).rejects.toBeInstanceOf(CMSError);
  });

  test('Different encapsulated plaintext should be rejected', async () => {
    // Let's tamper with the payload
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);
    const differentPlaintext = arrayBufferFrom('Different');
    // tslint:disable-next-line:no-object-mutation
    signedData.pkijsSignedData.encapContentInfo = new pkijs.EncapsulatedContentInfo({
      eContent: new asn1js.OctetString({ valueHex: differentPlaintext }),
      eContentType: CMS_OIDS.DATA,
    });

    await expect(signedData.verify()).rejects.toBeInstanceOf(CMSError);
  });

  test('Invalid signature should be rejected', async () => {
    // Let's tamper with the signature
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);
    const differentSignature = arrayBufferFrom('Different');
    // tslint:disable-next-line:no-object-mutation
    signedData.pkijsSignedData.signerInfos[0].signature = new asn1js.OctetString({
      valueHex: differentSignature,
    });

    await expect(signedData.verify()).rejects.toThrowWithMessage(
      CMSError,
      'Invalid signature (PKI.js code: 14)',
    );
  });

  test('Valid signature without encapsulated plaintext should be accepted', async () => {
    const signedData = await SignedData.sign(
      plaintext,
      keyPair.privateKey,
      certificate,
      undefined,
      {
        encapsulatePlaintext: false,
      },
    );

    await signedData.verify(plaintext);
  });

  test('Valid signature with encapsulated plaintext should be accepted', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);
    await signedData.verify();
  });
});

describe('plaintext', () => {
  test('Nothing should be output if plaintext is absent', async () => {
    const pkijsSignedData = new pkijs.SignedData();
    const signedData = new SignedData(pkijsSignedData);

    await expect(signedData.plaintext).toBeNull();
  });

  test('Plaintext should be output if present', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

    expectArrayBuffersToEqual(plaintext, signedData.plaintext!);
  });

  test('Large plaintexts chunked by PKI.js should be put back together', async () => {
    const largePlaintext = arrayBufferFrom('a'.repeat(2 ** 20));
    const signedData = await SignedData.sign(largePlaintext, keyPair.privateKey, certificate);

    expectArrayBuffersToEqual(largePlaintext, signedData.plaintext!);
  });
});

describe('signerCertificate', () => {
  test('Nothing should be output if there are no SignerInfo values', async () => {
    const signerCertificate = await generateStubCert({
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
    });
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, signerCertificate);
    signedData.pkijsSignedData.signerInfos.pop();

    expect(signedData.signerCertificate).toBeNull();
  });

  test('Certificate with same issuer but different SN should be ignored', async () => {
    const signerCertificate = await generateStubCert({
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
    });
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, signerCertificate);
    signedData.pkijsSignedData.signerInfos.forEach((signerInfo) => {
      (signerInfo.sid as pkijs.IssuerAndSerialNumber).serialNumber = new asn1js.Integer({
        value: -1,
      });
    });

    expect(signedData.signerCertificate).toBeNull();
  });

  test('Certificate with same SN but different issuer should be ignored', async () => {
    const signerCertificate = await generateStubCert({
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
    });
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, signerCertificate);
    signedData.pkijsSignedData.signerInfos.forEach((si) => {
      (si.sid as pkijs.IssuerAndSerialNumber).issuer = new pkijs.RelativeDistinguishedNames();
    });

    expect(signedData.signerCertificate).toBeNull();
  });

  test('Certificate with same SN and issuer should be output', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

    expect(signedData.signerCertificate?.isEqual(certificate)).toBeTrue();
  });
});

describe('certificates', () => {
  test('Attached CA certificates should be output', async () => {
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
    const signedData = await SignedData.sign(
      plaintext,
      signerKeyPair.privateKey,
      signerCertificate,
      [intermediateCaCertificate, rootCaCertificate],
    );

    const certificates = Array.from(signedData.certificates);
    expect(certificates.filter((c) => c.isEqual(rootCaCertificate))).toHaveLength(1);
    expect(certificates.filter((c) => c.isEqual(intermediateCaCertificate))).toHaveLength(1);
    expect(certificates.filter((c) => c.isEqual(signerCertificate))).toHaveLength(1);
  });
});

function getSignerInfoAttribute(
  signerInfo: pkijs.SignerInfo,
  attributeOid: string,
): pkijs.Attribute {
  const attributes = (signerInfo.signedAttrs as pkijs.SignedAndUnsignedAttributes).attributes;
  const matchingAttrs = attributes.filter((a) => a.type === attributeOid);
  expect(matchingAttrs).toHaveLength(1);
  return matchingAttrs[0];
}
