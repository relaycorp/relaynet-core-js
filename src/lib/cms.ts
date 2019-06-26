import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { getPkijsCrypto } from './_utils';
import * as oids from './oids';
import Certificate from './pki/Certificate';

const pkijsCrypto = getPkijsCrypto();

export async function sign(
  plaintext: ArrayBuffer,
  signerCertificate: Certificate
): Promise<ArrayBuffer> {
  const digest = await pkijsCrypto.digest({ name: 'SHA-256' }, plaintext);
  const signerInfo = new pkijs.SignerInfo({
    sid: new pkijs.IssuerAndSerialNumber({
      issuer: signerCertificate.pkijsCertificate.issuer,
      serialNumber: signerCertificate.pkijsCertificate.serialNumber
    }),
    signedAttrs: new pkijs.SignedAndUnsignedAttributes({
      attributes: [
        new pkijs.Attribute({
          type: oids.CMS_ATTR_CONTENT_TYPE,
          values: [new asn1js.ObjectIdentifier({ value: oids.CMS_DATA })]
        }),
        new pkijs.Attribute({
          type: oids.CMS_ATTR_DIGEST,
          values: [new asn1js.OctetString({ valueHex: digest })]
        })
      ],
      type: 0
    }),
    version: 1
  });
  const cmsSigned = new pkijs.SignedData({
    signerInfos: [signerInfo],
    version: 1
  });
  const contentInfo = new pkijs.ContentInfo({
    content: cmsSigned.toSchema(true),
    contentType: oids.CMS_SIGNED_DATA
  });
  return contentInfo.toSchema().toBER(false);
}
